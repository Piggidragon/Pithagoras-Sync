//! TLS for every connection to a portal that is not on this machine.
//!
//! With a pin (from the pairing URI) the certificate must carry exactly that public
//! key, whoever signed it: a self-signed portal certificate works, and a CA cannot
//! substitute another key. Without a pin the certificate is checked against the
//! system's root certificates as a browser would.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

/// The pin of a certificate: base64url (no padding) sha256 of its
/// SubjectPublicKeyInfo, the same value `openssl ... | openssl dgst -sha256` gives.
pub fn pin_of_cert(cert_der: &[u8]) -> Option<String> {
    spki_of(cert_der).map(pin_of_spki)
}

pub fn pin_of_spki(spki_der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, spki_der))
}

/// Checks a pin's form and returns its 32 bytes.
pub fn decode_pin(pin: &str) -> Result<[u8; 32], String> {
    let raw = URL_SAFE_NO_PAD
        .decode(pin.trim_end_matches('='))
        .map_err(|_| "the certificate pin is not base64url".to_string())?;
    raw.try_into()
        .map_err(|_| "the certificate pin is not a sha256 hash".to_string())
}

/// The SubjectPublicKeyInfo element (tag and length included) of an X.509
/// certificate in DER.
pub fn spki_of(cert: &[u8]) -> Option<&[u8]> {
    let (tag, cert_body, _) = der_element(cert)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, tbs, _) = der_element(cert_body)?;
    if tag != 0x30 {
        return None;
    }
    let mut rest = tbs;
    // version [0] EXPLICIT is optional.
    let (tag, _, after) = der_element(rest)?;
    if tag == 0xa0 {
        rest = after;
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        let (_, _, after) = der_element(rest)?;
        rest = after;
    }
    let (tag, _, after) = der_element(rest)?;
    if tag != 0x30 {
        return None;
    }
    Some(&rest[..rest.len() - after.len()])
}

/// The tag, contents and remainder of the DER element at the start of `d`.
fn der_element(d: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *d.first()?;
    // Multi-byte tags do not occur in the parts of a certificate walked here.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *d.get(1)?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *d.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    if end > d.len() {
        return None;
    }
    Some((tag, &d[header..end], &d[end..]))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The client configuration for a portal: pinned when `pin` is set, else the
/// system's roots.
pub fn client_config(pin: Option<&str>) -> Result<Arc<ClientConfig>, String> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let config = match pin {
        Some(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier {
                pin: decode_pin(pin)?,
                algs: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth(),
        None => {
            let loaded = rustls_native_certs::load_native_certs();
            let mut roots = rustls::RootCertStore::empty();
            let (added, _) = roots.add_parsable_certificates(loaded.certs);
            if added == 0 {
                return Err(
                    "no system root certificates found; pair with a URI that carries the certificate pin"
                        .into(),
                );
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    Ok(Arc::new(config))
}

/// Accepts exactly the pinned key. The handshake signature is still verified, so
/// the server has to hold the private key; name and expiry do not matter, as with
/// an ssh host key.
#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let spki = spki_of(end_entity.as_ref())
            .ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let got = ring::digest::digest(&ring::digest::SHA256, spki);
        // The pin is public (it is in the pairing URI), so a plain comparison is fine.
        if got.as_ref() == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_need_32_bytes() {
        assert!(decode_pin(&"A".repeat(43)).is_ok());
        assert!(decode_pin("AAAA").is_err());
        assert!(decode_pin("not base64!").is_err());
    }

    #[test]
    fn der_walker_refuses_truncated_input() {
        assert!(spki_of(&[]).is_none());
        assert!(spki_of(&[0x30, 0x05, 0x30]).is_none());
        assert!(spki_of(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
    }
}

//! Signing as minisign does: legacy Ed25519 signatures (`Ed`, the message signed as
//! it is) with a trusted comment. The client verifies them with `minisign-verify`.
//! The public key is minisign's; the secret key file is this tool's own: the key
//! id and the PKCS#8 document, in base64, without a password (the release key
//! lives in a CI secret, test keys in temp dirs).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};

pub struct SigningKey {
    pair: Ed25519KeyPair,
    pkcs8: Vec<u8>,
    key_id: [u8; 8],
}

impl SigningKey {
    pub fn generate() -> SigningKey {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .unwrap()
            .as_ref()
            .to_vec();
        let mut key_id = [0u8; 8];
        rng.fill(&mut key_id).unwrap();
        SigningKey::from_parts(&pkcs8, key_id)
    }

    fn from_parts(pkcs8: &[u8], key_id: [u8; 8]) -> SigningKey {
        SigningKey {
            pair: Ed25519KeyPair::from_pkcs8(pkcs8).unwrap(),
            pkcs8: pkcs8.to_vec(),
            key_id,
        }
    }

    /// The key as a file: the key id, then the PKCS#8 document, in base64.
    pub fn export(&self) -> String {
        let mut b = self.key_id.to_vec();
        b.extend_from_slice(&self.pkcs8);
        STANDARD.encode(b)
    }

    pub fn import(s: &str) -> Result<SigningKey, String> {
        let b = STANDARD.decode(s.trim()).map_err(|e| e.to_string())?;
        if b.len() < 9 {
            return Err("not a signing key".into());
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&b[..8]);
        Ed25519KeyPair::from_pkcs8(&b[8..]).map_err(|e| e.to_string())?;
        Ok(SigningKey::from_parts(&b[8..], key_id))
    }

    /// The public key as minisign writes it on the second line of `minisign.pub`.
    pub fn public_base64(&self) -> String {
        let mut b = b"Ed".to_vec();
        b.extend_from_slice(&self.key_id);
        b.extend_from_slice(self.pair.public_key().as_ref());
        STANDARD.encode(b)
    }

    /// A `.minisig` file for `data`.
    pub fn sign(&self, data: &[u8], trusted_comment: &str) -> String {
        let sig = self.pair.sign(data);
        let mut bin1 = b"Ed".to_vec();
        bin1.extend_from_slice(&self.key_id);
        bin1.extend_from_slice(sig.as_ref());
        let mut global = sig.as_ref().to_vec();
        global.extend_from_slice(trusted_comment.as_bytes());
        let global = self.pair.sign(&global);
        format!(
            "untrusted comment: signature from a pithagoras-sync release key\n{}\ntrusted comment: {trusted_comment}\n{}\n",
            STANDARD.encode(bin1),
            STANDARD.encode(global.as_ref())
        )
    }
}

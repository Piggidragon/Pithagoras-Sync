//! A minisign signature by the release key: the one check behind the update
//! manifest and the computer-use pins document.

/// Whether `sig` is a valid signature of `data` by `key` (minisign, base64).
/// `what` names the file in the errors (`manifest`, `pins document`).
pub fn verify(data: &[u8], sig: &str, key: &str, what: &str) -> Result<(), String> {
    let key = minisign_verify::PublicKey::from_base64(key.trim())
        .map_err(|e| format!("the update key of this build is unusable: {e}"))?;
    let sig = minisign_verify::Signature::decode(sig)
        .map_err(|e| format!("the {what}'s signature is unreadable: {e}"))?;
    // Legacy (non-prehashed) signatures are taken too: the files are small, and
    // Ed25519 over the whole of them is as strong.
    key.verify(data, &sig, true)
        .map_err(|e| format!("the {what}'s signature does not verify: {e}"))
}

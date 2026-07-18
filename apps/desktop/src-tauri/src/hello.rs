//! Windows Hello unlock gate. When enabled (Settings), the app starts locked and requires a
//! Hello verification (face / fingerprint / PIN) before the vault key is loaded from the
//! keychain. This is a per-unlock UI gate on top of the OS-keychain at-rest protection —
//! someone sitting at your already-logged-in PC can't open the vault without Hello.
//!
//! On non-Windows targets these are no-ops (available=false, verify=pass).

/// Is a Windows Hello verifier available on this device?
#[cfg(windows)]
pub fn available() -> bool {
    use windows::Security::Credentials::UI::{
        UserConsentVerifier, UserConsentVerifierAvailability,
    };
    (|| -> windows::core::Result<bool> {
        let avail = UserConsentVerifier::CheckAvailabilityAsync()?.get()?;
        Ok(avail == UserConsentVerifierAvailability::Available)
    })()
    .unwrap_or(false)
}

/// Prompt for Windows Hello. Ok(true) = verified, Ok(false) = user declined/failed.
#[cfg(windows)]
pub fn verify(message: &str) -> Result<bool, String> {
    use windows::core::HSTRING;
    use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
    let op = UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(message))
        .map_err(|e| e.to_string())?;
    let res = op.get().map_err(|e| e.to_string())?;
    Ok(res == UserConsentVerificationResult::Verified)
}

#[cfg(not(windows))]
pub fn available() -> bool {
    false
}

#[cfg(not(windows))]
pub fn verify(_message: &str) -> Result<bool, String> {
    Ok(true)
}

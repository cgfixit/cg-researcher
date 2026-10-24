//! Native macOS Keychain access through Security.framework (`SecItem*`).
//!
//! It replaces the `/usr/bin/security add-generic-password -w <value>` call,
//! which put the secret on argv where same-user `ps` could see it.
//! The value now never leaves this process except through the framework.
//!
//! On macOS each keychain item's ACL is tied to the creating binary's code
//! signature. An ad-hoc-signed rebuild has a new identity, so the first read
//! after an upgrade shows a one-time "Always Allow" prompt. A stable Developer
//! ID signature removes that prompt. This is documented in SECURITY.md.

/// `errSecItemNotFound` from `<Security/SecBase.h>`.
pub const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain item not found")]
    NotFound,
    #[error("keychain error {0}")]
    Os(i32),
    #[error("keychain value is not UTF-8")]
    NotUtf8,
    #[error("keychain is only available on macOS")]
    Unsupported,
}

#[cfg(target_os = "macos")]
fn map(e: security_framework::base::Error) -> KeychainError {
    if e.code() == ERR_SEC_ITEM_NOT_FOUND {
        KeychainError::NotFound
    } else {
        KeychainError::Os(e.code())
    }
}

/// Read a generic password (service, account).
pub fn get(service: &str, account: &str) -> Result<String, KeychainError> {
    #[cfg(target_os = "macos")]
    {
        let opts =
            security_framework::passwords::PasswordOptions::new_generic_password(service, account);
        let bytes = security_framework::passwords::generic_password(opts).map_err(map)?;
        String::from_utf8(bytes).map_err(|_| KeychainError::NotUtf8)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, account);
        Err(KeychainError::Unsupported)
    }
}

/// Create or update a generic password.
pub fn set(service: &str, account: &str, value: &str) -> Result<(), KeychainError> {
    #[cfg(target_os = "macos")]
    {
        security_framework::passwords::set_generic_password(service, account, value.as_bytes())
            .map_err(map)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, account, value);
        Err(KeychainError::Unsupported)
    }
}

/// Delete a generic password; a missing item counts as success.
pub fn delete(service: &str, account: &str) -> Result<(), KeychainError> {
    #[cfg(target_os = "macos")]
    {
        match security_framework::passwords::delete_generic_password(service, account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(map(e)),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, account);
        Err(KeychainError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real Keychain round trip. `#[ignore]` because it needs an unlocked
    /// default keychain. CI's macOS job creates a throwaway keychain and runs
    /// this with `--ignored`.
    #[test]
    #[ignore = "needs an unlocked macOS keychain; run in CI macos job"]
    fn keychain_roundtrip() {
        let svc = "cg-researcher-test";
        let acct = format!("roundtrip-{}", std::process::id());
        set(svc, &acct, "v1-secret").expect("set");
        set(svc, &acct, "v2-secret").expect("update");
        assert_eq!(get(svc, &acct).expect("get"), "v2-secret");
        delete(svc, &acct).expect("delete");
        assert!(matches!(get(svc, &acct), Err(KeychainError::NotFound)));
        delete(svc, &acct).expect("idempotent delete");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_is_explicitly_unsupported() {
        assert!(matches!(get("s", "a"), Err(KeychainError::Unsupported)));
        assert!(matches!(
            set("s", "a", "v"),
            Err(KeychainError::Unsupported)
        ));
    }
}

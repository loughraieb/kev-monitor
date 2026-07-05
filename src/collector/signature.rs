//! Phase 3 — Authenticode signature verification via `WinVerifyTrust` (windows 0.62).
//!
//! The public API [`verify_file`] returns a value and never panics or propagates an error
//! that could abort a scan: a verification failure becomes a [`SignatureResult`] with
//! `signed: false` and an `error` string. State allocated by the VERIFY action is always
//! released by a matching CLOSE action via an RAII guard.
//!
//! Publisher extraction is intentionally deferred to Phase 3b; `publisher` is always `None`
//! here. Getting `signed`/`chain_valid`/`revoked` correct and tested comes first.

/// Outcome of verifying one image file.
#[derive(Debug, Clone, Default)]
pub struct SignatureResult {
    pub signed: bool,
    pub chain_valid: bool,
    pub revoked: bool,
    pub publisher: Option<String>,
    /// Non-fatal diagnostic when verification could not be completed or returned an
    /// unmapped status.
    pub error: Option<String>,
}

impl From<SignatureResult> for crate::model::Signature {
    fn from(r: SignatureResult) -> Self {
        crate::model::Signature {
            signed: r.signed,
            publisher: r.publisher,
            chain_valid: r.chain_valid,
            revoked: r.revoked,
        }
    }
}

/// Verify the Authenticode signature of the file at `path`.
///
/// `online_revocation` selects `WTD_REVOKE_WHOLECHAIN` (online OCSP/CRL) when true, or
/// `WTD_REVOKE_NONE` when false. Never panics; failures are reported in
/// [`SignatureResult::error`].
pub fn verify_file(path: &str, online_revocation: bool) -> SignatureResult {
    #[cfg(windows)]
    {
        windows_impl::verify(path, online_revocation)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, online_revocation);
        SignatureResult {
            error: Some("signature verification is only available on Windows".into()),
            ..Default::default()
        }
    }
}

/// Map a `WinVerifyTrust` return code (a LONG/HRESULT) to a [`SignatureResult`].
///
/// Uses documented HRESULT bit-patterns directly so it does not depend on the exact module
/// path / newtype of the generated `windows` constants.
fn interpret(rc: i32) -> SignatureResult {
    // Documented WinVerifyTrust status codes (winerror.h), as i32 bit-patterns.
    const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800B0111u32 as i32;
    const TRUST_E_SUBJECT_NOT_TRUSTED: i32 = 0x800B0004u32 as i32;
    const TRUST_E_BAD_DIGEST: i32 = 0x80096010u32 as i32;
    const CERT_E_REVOKED: i32 = 0x800B010Cu32 as i32;
    const CERT_E_EXPIRED: i32 = 0x800B0101u32 as i32;
    const CERT_E_UNTRUSTEDROOT: i32 = 0x800B0109u32 as i32;
    const CERT_E_CHAINING: i32 = 0x800B010Au32 as i32;

    match rc {
        // ERROR_SUCCESS: signed and the whole chain verified to a trusted root.
        0 => SignatureResult { signed: true, chain_valid: true, ..Default::default() },
        // Has a signature, but a cert in the chain is revoked.
        CERT_E_REVOKED => {
            SignatureResult { signed: true, chain_valid: false, revoked: true, ..Default::default() }
        }
        // No signature present at all.
        TRUST_E_NOSIGNATURE => SignatureResult { signed: false, ..Default::default() },
        // Signed, but the chain does not establish trust for one of these reasons.
        CERT_E_EXPIRED
        | CERT_E_UNTRUSTEDROOT
        | CERT_E_CHAINING
        | TRUST_E_SUBJECT_NOT_TRUSTED
        | TRUST_E_EXPLICIT_DISTRUST
        | TRUST_E_BAD_DIGEST => {
            SignatureResult { signed: true, chain_valid: false, ..Default::default() }
        }
        // Anything else: record the raw code, treat as not-verified.
        other => SignatureResult {
            error: Some(format!("WinVerifyTrust rc=0x{:08X}", other as u32)),
            ..Default::default()
        },
    }
}

/// HRESULT bit-pattern for "no embedded signature" — the signal to try a catalog.
const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;

#[cfg(windows)]
mod windows_impl {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;

    use windows::core::{GUID, PCWSTR};
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    // Catalog admin/info handles are plain `isize` in windows 0.62 (not newtypes).
    type HCatAdmin = isize;
    type HCatInfo = isize;
    use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO,
        WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };

    use super::{interpret, SignatureResult, TRUST_E_NOSIGNATURE};

    /// Read the signing publisher (subject display name) from a completed WinVerifyTrust state.
    /// Works for both embedded and catalog signatures since both build a provider chain.
    ///
    /// SAFETY: `state` must be the `hWVTStateData` of a successful (rc == 0) VERIFY whose CLOSE
    /// hasn't run yet. The provider/signer/cert pointers are borrows into WinTrust-owned state —
    /// read here, never freed by us; CLOSE (via `CloseGuard`) frees them afterwards.
    unsafe fn publisher_from_state(state: HANDLE) -> Option<String> {
        if state.0.is_null() {
            return None;
        }
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() || (*sgnr).csCertChain == 0 {
            return None;
        }
        let pcert = WTHelperGetProvCertFromChain(sgnr, 0);
        if pcert.is_null() || (*pcert).pCert.is_null() {
            return None;
        }
        let cert = (*pcert).pCert;
        let len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
        if len <= 1 {
            return None;
        }
        let mut buf = vec![0u16; len as usize];
        let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
        if n <= 1 {
            return None;
        }
        let s = String::from_utf16_lossy(&buf[..n as usize - 1]).trim().to_string();
        (!s.is_empty()).then_some(s)
    }

    fn to_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn revocation_flag(online: bool) -> windows::Win32::Security::WinTrust::WINTRUST_DATA_REVOCATION_CHECKS {
        if online {
            WTD_REVOKE_WHOLECHAIN
        } else {
            WTD_REVOKE_NONE
        }
    }

    /// Ensures the WinVerifyTrust state allocated by VERIFY is freed by a CLOSE call, even
    /// if code between VERIFY and CLOSE panics. Holds raw pointers to stack locals that
    /// outlive the guard (guard is declared last, so it drops first).
    struct CloseGuard {
        action: *mut GUID,
        data: *mut WINTRUST_DATA,
    }

    impl Drop for CloseGuard {
        fn drop(&mut self) {
            // SAFETY: `data`/`action` point at live stack locals; the same `data` was passed
            // to VERIFY so `hWVTStateData` round-trips here.
            unsafe {
                (*self.data).dwStateAction = WTD_STATEACTION_CLOSE;
                let _ = WinVerifyTrust(HWND::default(), self.action, self.data as *mut c_void);
            }
        }
    }

    /// Public entry: try embedded signature, then fall back to catalog (system binaries are
    /// catalog-signed). Never panics.
    pub fn verify(path: &str, online: bool) -> SignatureResult {
        let (rc, publisher) = verify_embedded(path, online);
        if rc != TRUST_E_NOSIGNATURE {
            return SignatureResult { publisher, ..interpret(rc) };
        }
        // No embedded signature — is the file catalog-signed?
        match verify_catalog(path, online) {
            CatalogOutcome::Verified(crc, pubname) => {
                SignatureResult { publisher: pubname, ..interpret(crc) }
            }
            CatalogOutcome::NoCatalog => interpret(rc), // genuinely unsigned
            CatalogOutcome::Error(e) => SignatureResult { error: Some(e), ..interpret(rc) },
        }
    }

    /// Verify an embedded Authenticode signature; returns the raw WinVerifyTrust code and, when
    /// trusted, the signing publisher.
    fn verify_embedded(path: &str, online: bool) -> (i32, Option<String>) {
        let wide = to_wide(path);
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: revocation_flag(online),
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file_info as *mut WINTRUST_FILE_INFO },
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let _guard = CloseGuard { action: &mut action, data: &mut data };
        // SAFETY: all pointed-to data lives on the stack through VERIFY and the guard's CLOSE.
        let rc = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action as *mut GUID,
                &mut data as *mut WINTRUST_DATA as *mut c_void,
            )
        };
        // Read the signer from the trust state while it's still open (guard runs CLOSE after).
        let publisher = if rc == 0 {
            unsafe { publisher_from_state(data.hWVTStateData) }
        } else {
            None
        };
        (rc, publisher)
    }

    enum CatalogOutcome {
        Verified(i32, Option<String>),
        NoCatalog,
        Error(String),
    }

    /// Release the catalog admin context on drop.
    struct AdminGuard(HCatAdmin);
    impl Drop for AdminGuard {
        fn drop(&mut self) {
            // SAFETY: handle came from a successful AcquireContext2.
            unsafe {
                let _ = CryptCATAdminReleaseContext(self.0, 0);
            }
        }
    }

    /// Release the catalog context on drop.
    struct CatInfoGuard {
        admin: HCatAdmin,
        info: HCatInfo,
    }
    impl Drop for CatInfoGuard {
        fn drop(&mut self) {
            // SAFETY: both handles came from successful calls above.
            unsafe {
                let _ = CryptCATAdminReleaseCatalogContext(self.admin, self.info, 0);
            }
        }
    }

    /// Locate the system catalog that vouches for `path` and verify it. Returns `NoCatalog`
    /// when the file's hash isn't in any catalog (i.e. it really is unsigned).
    fn verify_catalog(path: &str, online: bool) -> CatalogOutcome {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => return CatalogOutcome::Error(format!("catalog open: {e}")),
        };
        let hfile = HANDLE(file.as_raw_handle());
        let sha256 = to_wide("SHA256");

        // SHA256 catalog admin context.
        let mut hcatadmin: HCatAdmin = 0;
        // SAFETY: out-param handle; algorithm string is NUL-terminated and lives in `sha256`.
        if let Err(e) = unsafe {
            CryptCATAdminAcquireContext2(&mut hcatadmin, None, PCWSTR(sha256.as_ptr()), None, None)
        } {
            return CatalogOutcome::Error(format!("catalog acquire: {e}"));
        }
        let _admin = AdminGuard(hcatadmin);

        // Compute the file's catalog hash (size query, then fill).
        let mut cb: u32 = 0;
        // SAFETY: size query — `None` buffer with cb=0 returns the needed length in `cb`.
        unsafe {
            let _ = CryptCATAdminCalcHashFromFileHandle2(hcatadmin, hfile, &mut cb, None, None);
        }
        if cb == 0 {
            return CatalogOutcome::Error("catalog hash length 0".into());
        }
        let mut hash = vec![0u8; cb as usize];
        // SAFETY: `hash` is `cb` bytes as reported by the size query.
        if let Err(e) = unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                hcatadmin,
                hfile,
                &mut cb,
                Some(hash.as_mut_ptr()),
                None,
            )
        } {
            return CatalogOutcome::Error(format!("catalog hash: {e}"));
        }

        // Find a catalog containing that hash.
        // SAFETY: `hash` is the full computed hash; `None` prev-context starts enumeration.
        let hcatinfo: HCatInfo =
            unsafe { CryptCATAdminEnumCatalogFromHash(hcatadmin, &hash, None, None) };
        if hcatinfo == 0 {
            return CatalogOutcome::NoCatalog;
        }
        let _cat = CatInfoGuard { admin: hcatadmin, info: hcatinfo };

        // Resolve the catalog file path.
        let mut info = CATALOG_INFO {
            cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        // SAFETY: `hcatinfo` is a valid catalog context.
        if let Err(e) = unsafe { CryptCATCatalogInfoFromContext(hcatinfo, &mut info, 0) } {
            return CatalogOutcome::Error(format!("catalog info: {e}"));
        }

        // Member tag is the uppercase-hex of the file hash.
        let mut tag = String::with_capacity(hash.len() * 2);
        for b in &hash {
            use std::fmt::Write as _;
            let _ = write!(tag, "{b:02X}");
        }
        let tag_wide = to_wide(&tag);
        let member_wide = to_wide(path);

        let mut cat_info = WINTRUST_CATALOG_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
            pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
            pcwszMemberTag: PCWSTR(tag_wide.as_ptr()),
            pcwszMemberFilePath: PCWSTR(member_wide.as_ptr()),
            hMemberFile: hfile,
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: cb,
            hCatAdmin: hcatadmin,
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: revocation_flag(online),
            dwUnionChoice: WTD_CHOICE_CATALOG,
            Anonymous: WINTRUST_DATA_0 { pCatalog: &mut cat_info as *mut WINTRUST_CATALOG_INFO },
            dwStateAction: WTD_STATEACTION_VERIFY,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let _guard = CloseGuard { action: &mut action, data: &mut data };
        // SAFETY: all referenced buffers (`hash`, `tag_wide`, `member_wide`, `info`, `cat_info`,
        // `data`, `action`) and `file` live through VERIFY and the guard's CLOSE. `file` is
        // declared first, so it (and `hfile`) outlive every guard's teardown.
        let rc = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action as *mut GUID,
                &mut data as *mut WINTRUST_DATA as *mut c_void,
            )
        };
        let publisher = if rc == 0 {
            unsafe { publisher_from_state(data.hWVTStateData) }
        } else {
            None
        };
        CatalogOutcome::Verified(rc, publisher)
    }
}

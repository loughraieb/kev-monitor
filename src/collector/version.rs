//! Read a binary's `FileDescription` from its PE version-info resource — i.e. what the file
//! *claims to be* (e.g. "Google Chrome"). This is identity, **not** a legitimacy signal: the
//! string is attacker-controllable, so a malicious file can claim any description. The engine
//! uses it only for display ("what it looks like"), never for scoring.

/// Best-effort `FileDescription` for the image at `path`. `None` if the file has no version
/// resource or it can't be read.
#[cfg(windows)]
pub fn file_description(path: &str) -> Option<String> {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;

    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    let wpath = wide(path);
    unsafe {
        let size = GetFileVersionInfoSizeW(PCWSTR(wpath.as_ptr()), None);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        GetFileVersionInfoW(PCWSTR(wpath.as_ptr()), None, size, buf.as_mut_ptr() as *mut c_void)
            .ok()?;

        // Languages present in the resource (each is language + codepage), plus common defaults.
        let mut langs: Vec<(u16, u16)> = Vec::new();
        let tkey = wide("\\VarFileInfo\\Translation");
        let mut tptr: *mut c_void = std::ptr::null_mut();
        let mut tlen: u32 = 0;
        if VerQueryValueW(buf.as_ptr() as *const c_void, PCWSTR(tkey.as_ptr()), &mut tptr, &mut tlen)
            .as_bool()
            && !tptr.is_null()
            && tlen >= 4
        {
            let count = (tlen as usize) / 4;
            let arr = std::slice::from_raw_parts(tptr as *const u16, count * 2);
            for i in 0..count {
                langs.push((arr[i * 2], arr[i * 2 + 1]));
            }
        }
        langs.push((0x0409, 0x04b0)); // US English, Unicode
        langs.push((0x0409, 0x04e4)); // US English, multilingual

        for (lang, cp) in langs {
            let sub = wide(&format!("\\StringFileInfo\\{lang:04x}{cp:04x}\\FileDescription"));
            let mut vptr: *mut c_void = std::ptr::null_mut();
            let mut vlen: u32 = 0;
            if VerQueryValueW(buf.as_ptr() as *const c_void, PCWSTR(sub.as_ptr()), &mut vptr, &mut vlen)
                .as_bool()
                && !vptr.is_null()
                && vlen > 0
            {
                let s = std::slice::from_raw_parts(vptr as *const u16, vlen as usize);
                let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                let desc = String::from_utf16_lossy(&s[..end]).trim().to_string();
                if !desc.is_empty() {
                    return Some(desc);
                }
            }
        }
        None
    }
}

#[cfg(not(windows))]
pub fn file_description(_path: &str) -> Option<String> {
    None
}

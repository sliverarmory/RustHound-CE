//! Remote Registry reads using the current Windows logon session.
//!
//! RegConnectRegistryW authenticates through Windows rather than requiring the
//! collector to handle a password or NT hash. Keep the returned handles scoped
//! to the blocking thread which made the calls.

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr;

type Hkey = *mut c_void;

const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002u32 as i32 as isize as Hkey;
const HKEY_USERS: Hkey = 0x8000_0003u32 as i32 as isize as Hkey;
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_MORE_DATA: i32 = 234;
const ERROR_NO_MORE_ITEMS: i32 = 259;
const KEY_QUERY_VALUE: u32 = 0x0001;
const REG_DWORD: u32 = 4;
const MAX_SUBKEYS: u32 = 100_000;

#[link(name = "advapi32")]
extern "system" {
    fn RegConnectRegistryW(machine: *const u16, root: Hkey, result: *mut Hkey) -> i32;
    fn RegOpenKeyExW(parent: Hkey, subkey: *const u16, options: u32, access: u32, result: *mut Hkey) -> i32;
    fn RegQueryValueExW(key: Hkey, name: *const u16, reserved: *mut u32, kind: *mut u32, data: *mut u8, size: *mut u32) -> i32;
    fn RegEnumKeyExW(key: Hkey, index: u32, name: *mut u16, name_len: *mut u32, reserved: *mut u32, class: *mut u16, class_len: *mut u32, modified: *mut c_void) -> i32;
    fn RegCloseKey(key: Hkey) -> i32;
}

struct OwnedHkey(Hkey);

impl Drop for OwnedHkey {
    fn drop(&mut self) {
        // Every OwnedHkey is returned by RegConnectRegistryW or RegOpenKeyExW.
        unsafe { RegCloseKey(self.0); }
    }
}

/// A connection to one remote predefined hive. Create, use, and drop it on
/// the same blocking thread; no handle is passed to an async worker.
pub(crate) struct RemoteRegistry {
    root: OwnedHkey,
}

fn wide(s: &str) -> Result<Vec<u16>, String> {
    if s.contains('\0') {
        return Err("registry path contains a NUL character".to_string());
    }
    Ok(OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect())
}

fn win_error(op: &str, code: i32) -> String {
    format!("{op} failed (win32 {code}: {})", std::io::Error::from_raw_os_error(code))
}

impl RemoteRegistry {
    fn connect(host: &str, hive: Hkey) -> Result<Self, String> {
        let machine = wide(&format!(r"\\{host}"))?;
        let mut root = ptr::null_mut();
        let status = unsafe { RegConnectRegistryW(machine.as_ptr(), hive, &mut root) };
        if status != ERROR_SUCCESS {
            return Err(win_error("RegConnectRegistryW", status));
        }
        if root.is_null() {
            return Err("RegConnectRegistryW returned a null registry handle".to_string());
        }
        Ok(Self { root: OwnedHkey(root) })
    }

    pub(crate) fn connect_hklm(host: &str) -> Result<Self, String> {
        Self::connect(host, HKEY_LOCAL_MACHINE)
    }

    pub(crate) fn connect_hku(host: &str) -> Result<Self, String> {
        Self::connect(host, HKEY_USERS)
    }

    /// A missing key or value is returned as None, as with the existing CA
    /// registry collector. Other errors must remain visible to BloodHound.
    pub(crate) fn read_dword(&self, subkey: &str, value: &str) -> Result<Option<u32>, String> {
        let subkey_w = wide(subkey)?;
        let value_w = wide(value)?;
        let mut key = ptr::null_mut();
        let status = unsafe { RegOpenKeyExW(self.root.0, subkey_w.as_ptr(), 0, KEY_QUERY_VALUE, &mut key) };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(win_error(&format!("RegOpenKeyExW({subkey})"), status));
        }
        if key.is_null() {
            return Err(format!("RegOpenKeyExW({subkey}) returned a null registry handle"));
        }
        let key = OwnedHkey(key);
        let mut kind = 0u32;
        let mut bytes = [0u8; 4];
        let mut size = bytes.len() as u32;
        let status = unsafe {
            RegQueryValueExW(key.0, value_w.as_ptr(), ptr::null_mut(), &mut kind, bytes.as_mut_ptr(), &mut size)
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(win_error(&format!("RegQueryValueExW({subkey}\\{value})"), status));
        }
        if kind != REG_DWORD {
            return Err(format!("{subkey}\\{value}: expected REG_DWORD, got registry type {kind}"));
        }
        if size != 4 {
            return Err(format!("{subkey}\\{value}: REG_DWORD value has {size} bytes, expected 4"));
        }
        Ok(Some(u32::from_le_bytes(bytes)))
    }

    /// Enumerate loaded HKU profile hives, matching dcerpc's logged_on_sids
    /// filter so both auth modes produce the same RegistrySessions results.
    pub(crate) fn logged_on_sids(&self) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for index in 0..MAX_SUBKEYS {
            let mut name = vec![0u16; 256];
            loop {
                let mut len = name.len() as u32;
                let status = unsafe {
                    RegEnumKeyExW(self.root.0, index, name.as_mut_ptr(), &mut len,
                        ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut())
                };
                if status == ERROR_NO_MORE_ITEMS {
                    return Ok(out);
                }
                if status == ERROR_MORE_DATA {
                    let needed = (len as usize).saturating_add(1).max(name.len().saturating_mul(2));
                    if needed > 16_384 {
                        return Err("RegEnumKeyExW returned an oversized HKU subkey".to_string());
                    }
                    name.resize(needed, 0);
                    continue;
                }
                if status != ERROR_SUCCESS {
                    return Err(win_error("RegEnumKeyExW(HKEY_USERS)", status));
                }
                let sid = String::from_utf16(&name[..len as usize])
                    .map_err(|e| format!("RegEnumKeyExW returned invalid UTF-16: {e}"))?;
                if sid.starts_with("S-1-5-21") && !sid.ends_with("_Classes") {
                    out.push(sid);
                }
                break;
            }
        }
        Err(format!("RegEnumKeyExW exceeded {MAX_SUBKEYS} HKU subkeys"))
    }
}

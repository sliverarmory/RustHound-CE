//! Discover the joined domain and a DNS-named DC for Windows integrated auth.

use std::ffi::c_void;
use std::ptr;

const DS_DIRECTORY_SERVICE_REQUIRED: u32 = 0x0000_0010;
const DS_RETURN_DNS_NAME: u32 = 0x4000_0000;

#[repr(C)]
struct DomainControllerInfo {
    domain_controller_name: *const u16,
    domain_controller_address: *const u16,
    domain_controller_address_type: u32,
    domain_guid: [u8; 16],
    domain_name: *const u16,
    dns_forest_name: *const u16,
    flags: u32,
    dc_site_name: *const u16,
    client_site_name: *const u16,
}

#[link(name = "Netapi32")]
extern "system" {
    fn DsGetDcNameW(
        computer_name: *const u16,
        domain_name: *const u16,
        domain_guid: *const c_void,
        site_name: *const u16,
        flags: u32,
        domain_controller_info: *mut *mut DomainControllerInfo,
    ) -> u32;
    fn NetApiBufferFree(buffer: *mut c_void) -> u32;
}

pub struct DiscoveredDomain {
    pub domain: String,
    pub dc_fqdn: String,
}

/// Use the machine's joined domain, or locate a DC for the supplied DNS domain.
/// The returned DC name is needed as the LDAP Kerberos service principal.
pub fn discover_domain_controller(domain: Option<&str>) -> Result<DiscoveredDomain, String> {
    let domain_wide = domain.map(|name| {
        name.encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>()
    });
    let domain_ptr = domain_wide.as_ref().map_or(ptr::null(), |name| name.as_ptr());
    let mut info = ptr::null_mut();
    // SAFETY: The optional UTF-16 input is NUL-terminated and lives through the call.
    // NetAPI allocates `info`, which is released below on every successful return.
    let status = unsafe {
        DsGetDcNameW(
            ptr::null(), domain_ptr, ptr::null(), ptr::null(),
            DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME,
            &mut info,
        )
    };
    if status != 0 {
        return Err(format!(
            "could not locate a domain controller for the current Windows logon (DsGetDcNameW error {status}); confirm this host is domain joined and can reach a DC"
        ));
    }
    if info.is_null() {
        return Err("DsGetDcNameW returned no domain controller".to_string());
    }
    // SAFETY: NetAPI returned a valid DOMAIN_CONTROLLER_INFO allocation and
    // NUL-terminated strings. Copy them before freeing the allocation.
    let (joined_domain, dc_fqdn) = unsafe {
        let joined_domain = wide_string((*info).domain_name);
        let dc_fqdn = wide_string((*info).domain_controller_name);
        NetApiBufferFree(info.cast());
        (joined_domain, dc_fqdn)
    };
    let dc_fqdn = dc_fqdn.trim_start_matches('\\').to_string();
    if joined_domain.is_empty() || dc_fqdn.is_empty() || !dc_fqdn.contains('.') {
        return Err("Windows DC discovery did not return DNS domain and DC names".to_string());
    }
    Ok(DiscoveredDomain { domain: joined_domain, dc_fqdn })
}

unsafe fn wide_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

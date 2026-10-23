//! Integrated Windows Kerberos material for the existing SMB2 transport.
//!
//! SSPI obtains a `cifs/<host>` ticket from the current logon session. We
//! convert its GSS Kerberos AP-REQ into the SPNEGO token expected by
//! `smb2-client` and query the resulting context key for SMB signing. No
//! password, hash, ticket, or key is written to disk.

use std::{ffi::c_void, net::IpAddr, ptr};

use anyhow::{anyhow, bail, Result};
use windows_sys::Win32::{
    Foundation::SEC_E_OK,
    Security::{
        Authentication::Identity::{
            AcquireCredentialsHandleW, DeleteSecurityContext, FreeContextBuffer,
            FreeCredentialsHandle, InitializeSecurityContextW, QueryContextAttributesW,
            SecBuffer, SecBufferDesc, SecPkgContext_SessionKey, ISC_REQ_ALLOCATE_MEMORY,
            ISC_REQ_CONNECTION, ISC_REQ_INTEGRITY, SECBUFFER_TOKEN, SECBUFFER_VERSION,
            SECPKG_ATTR_SESSION_KEY, SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP,
        },
        Credentials::SecHandle,
    },
};

const KRB5_OID_TLV: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

struct Credential(SecHandle);
impl Drop for Credential {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by AcquireCredentialsHandleW.
        unsafe { FreeCredentialsHandle(&self.0) };
    }
}

struct Context(SecHandle);
impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by InitializeSecurityContextW.
        unsafe { DeleteSecurityContext(&self.0) };
    }
}

struct ContextBuffer(*mut c_void);
impl Drop for ContextBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: SSPI allocated this buffer when ISC_REQ_ALLOCATE_MEMORY
            // was passed, or during QueryContextAttributesW.
            unsafe { FreeContextBuffer(self.0) };
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check_sspi(status: i32, operation: &str) -> Result<()> {
    if status == SEC_E_OK {
        Ok(())
    } else {
        Err(anyhow!("{operation} failed with SSPI status 0x{:08x}", status as u32))
    }
}

/// Return SPNEGO AP-REQ and the 16-byte SMB session key for `cifs/<host>`.
/// The identity is always the current Windows logon session.
pub fn current_user_smb_material(host: &str) -> Result<(Vec<u8>, [u8; 16])> {
    if host.is_empty() || host.contains('\0') || host.parse::<IpAddr>().is_ok() {
        bail!("current-user Kerberos SMB authentication requires a DNS host name");
    }

    let package = wide("Kerberos");
    let target = wide(&format!("cifs/{host}"));
    let mut cred_handle = SecHandle::default();
    let mut expiry = 0i64;
    // SAFETY: All pointers refer to live buffers or are the documented null
    // values. Null principal/auth data select the caller's logon credentials.
    let status = unsafe {
        AcquireCredentialsHandleW(
            ptr::null(), package.as_ptr(), SECPKG_CRED_OUTBOUND,
            ptr::null(), ptr::null(), None, ptr::null(),
            &mut cred_handle, &mut expiry,
        )
    };
    check_sspi(status, "AcquireCredentialsHandleW(Kerberos)")?;
    let cred = Credential(cred_handle);

    let mut context_handle = SecHandle::default();
    let mut output = SecBuffer {
        cbBuffer: 0,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: ptr::null_mut(),
    };
    let mut output_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut output,
    };
    let mut attributes = 0u32;
    // Do not request mutual authentication: smb2-client's Kerberos login is
    // single-shot. Do not request ISC_REQ_USE_SESSION_KEY: that can initiate
    // Kerberos user-to-user authentication instead of an ordinary service SPN.
    // SAFETY: The output descriptor is writable; SSPI allocates its token.
    let status = unsafe {
        InitializeSecurityContextW(
            &cred.0, ptr::null(), target.as_ptr(),
            ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY,
            0, SECURITY_NATIVE_DREP, ptr::null(), 0,
            &mut context_handle, &mut output_desc, &mut attributes, &mut expiry,
        )
    };
    let output_guard = ContextBuffer(output.pvBuffer);
    // A continuation token cannot be completed by smb2-client's one-shot API.
    check_sspi(status, "InitializeSecurityContextW(Kerberos)")?;
    let context = Context(context_handle);

    if output.cbBuffer == 0 || output.pvBuffer.is_null() {
        bail!("Kerberos SSPI returned no AP-REQ token");
    }
    // SAFETY: SSPI owns `output.pvBuffer` until output_guard is dropped.
    let token = unsafe {
        std::slice::from_raw_parts(output.pvBuffer.cast::<u8>(), output.cbBuffer as usize)
    };
    let ap_req = ap_req_from_gss_token(token)?;
    let spnego = super::gss::spnego_krb5_init(ap_req);

    let mut session_key = SecPkgContext_SessionKey::default();
    // SAFETY: `context.0` is a valid initialized context and the output
    // structure has the layout required by SECPKG_ATTR_SESSION_KEY.
    let status = unsafe {
        QueryContextAttributesW(
            &context.0, SECPKG_ATTR_SESSION_KEY,
            (&mut session_key as *mut SecPkgContext_SessionKey).cast::<c_void>(),
        )
    };
    check_sspi(status, "QueryContextAttributesW(SESSION_KEY)")?;
    let _key_guard = ContextBuffer(session_key.SessionKey.cast::<c_void>());
    if session_key.SessionKeyLength == 0 || session_key.SessionKey.is_null() {
        bail!("Kerberos SSPI returned an empty SMB session key");
    }
    // MS-SMB2 uses the first 16 bytes of the GSS key, padding a shorter key
    // with zero. The full SSPI key never leaves this function.
    let mut key = [0u8; 16];
    let copy_len = (session_key.SessionKeyLength as usize).min(key.len());
    // SAFETY: SSPI owns SessionKey for at least SessionKeyLength bytes until
    // _key_guard is dropped.
    unsafe { ptr::copy_nonoverlapping(session_key.SessionKey, key.as_mut_ptr(), copy_len) };
    drop(output_guard);
    Ok((spnego, key))
}

/// The Kerberos package emits a GSS InitialContextToken, while our existing
/// SPNEGO builder accepts a raw ASN.1 AP-REQ. Validate the OID and token ID
/// before removing the wrapper. A bare AP-REQ is also accepted for providers
/// that omit the GSS wrapper.
fn ap_req_from_gss_token(token: &[u8]) -> Result<&[u8]> {
    if token.first() == Some(&0x6e) {
        return Ok(token);
    }
    if token.first() != Some(&0x60) {
        bail!("Kerberos SSPI returned an unexpected token type");
    }
    let (len, header_len) = der_length(&token[1..])?;
    let inner_start = 1 + header_len;
    if len != token.len().saturating_sub(inner_start) {
        bail!("Kerberos SSPI returned a malformed GSS token length");
    }
    let inner = &token[inner_start..];
    if !inner.starts_with(KRB5_OID_TLV) {
        bail!("Kerberos SSPI token does not contain the Kerberos GSS OID");
    }
    let payload = &inner[KRB5_OID_TLV.len()..];
    if !payload.starts_with(&[0x01, 0x00, 0x6e]) {
        bail!("Kerberos SSPI token does not contain an AP-REQ");
    }
    Ok(&payload[2..])
}

fn der_length(input: &[u8]) -> Result<(usize, usize)> {
    let first = *input.first().ok_or_else(|| anyhow!("truncated GSS token"))?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > std::mem::size_of::<usize>() || input.len() <= count {
        bail!("invalid GSS token length");
    }
    let mut len = 0usize;
    for b in &input[1..=count] {
        len = len.checked_mul(256).and_then(|v| v.checked_add(*b as usize))
            .ok_or_else(|| anyhow!("GSS token length overflow"))?;
    }
    Ok((len, count + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwraps_gss_kerberos_ap_req() {
        let mut inner = KRB5_OID_TLV.to_vec();
        inner.extend_from_slice(&[0x01, 0x00, 0x6e, 0x00]);
        let mut token = vec![0x60, inner.len() as u8];
        token.extend_from_slice(&inner);
        assert_eq!(ap_req_from_gss_token(&token).unwrap(), &[0x6e, 0x00]);
    }

    #[test]
    fn rejects_non_kerberos_token() {
        assert!(ap_req_from_gss_token(&[0x60, 0x02, 0x01, 0x00]).is_err());
    }
}

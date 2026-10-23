# Sliver Armory extension

The `sliver-extension` feature exposes `RustHoundCE`, a native Sliver extension
entry point. The Windows amd64 build is packaged as `rusthound-ce.tar.gz` with
`extension.json` and a Minisign signature. Sliver loads the DLL bytes through
Reflektor. The collector stores LDAP results and its ZIP in target memory, then
returns the ZIP in bounded callback responses. It never receives an output path.

## Build and package

The release workflow builds the Windows MSVC DLL with:

```sh
cargo build --locked --release --target x86_64-pc-windows-msvc --lib \
  --no-default-features --features nogssapi,sliver-extension
```

For local cross builds, `x86_64-pc-windows-gnu` is also supported. Build a
manual package with `python3 scripts/package_armory.py --dll <dll> --version
2.5.29 --out <directory>`. The script writes an extension manifest containing
the DLL SHA-256 and a deterministic `rusthound-ce.tar.gz` archive.

The tagged release job signs the tar archive with the repository's
`MINISIGN_PRIVATE_KEY` Actions secret. Its trusted comment is the Base64 encoded
`extension.json`, as required by the Armory client. The package's public key is
published in the Armory index; the private key is never included in artifacts.

## Wire protocol

Call the `RustHoundCE` export with the Sliver native-extension ABI
`int RustHoundCE(char *request, uint32_t length, callback)`. Each call invokes
the callback exactly once with UTF-8 JSON. All requests include `version: 1`.

| Operation | Request fields | Response |
| --- | --- | --- |
| `start` | `domain`, `username`, `password`, optional `method`, `ldapFqdn`, `ip`, `port`, `ldaps`, `ldapFilter`, `maxBytes`, `timeoutSeconds` | `state: "running"`, `runId` |
| `status` | `runId` | `state: "running"`, `"complete"`, or `"error"`; completed runs include `size` and lowercase `sha256` |
| `read` | `runId`, `offset`, `maxBytes` | `state: "chunk"`, `offset`, `nextOffset`, Base64 `data` |
| `finish` | `runId` | `state: "finished"`; ZIP memory is cleared |
| `abort` | `runId` | `state: "aborted"`; a running worker is cancelled and its slot is released after it exits |

Methods are `LdapOnly` (default), `DCOnly`, and `All`. A bare username is
expanded to `user@domain` for simple LDAP bind. Password is mandatory; the
extension will not prompt. Current-token SSPI is not yet supported. The
credential lives only in the active worker, not in the run registry. Operators
should be aware that Sliver may persist beacon task requests on its server.

The current LDAP transport defaults to simple bind on port 389, which can send
the password over the network without encryption. Setting `ldaps: true` uses
TLS, but upstream RustHound currently disables DC certificate verification;
therefore this mode encrypts traffic without authenticating the DC. Do not
present the LDAPS option as a verified or authenticated connection. Use only
under a network and credential policy that permits these properties. Verified
LDAPS or StartTLS with operator-supplied trust roots requires a later transport
change and its own GOAD validation.

Read chunks are limited to 32,768 raw bytes so Base64 responses fit existing
beacon task-content limits. ZIP output defaults to 256 MiB and cannot exceed
1 GiB. LDAP input is capped at the smaller of the ZIP limit and 512 MiB,
plus a one-million-object limit. The worker defaults to a ten-minute timeout;
the maximum is one hour. One run may be registered per implant at a time.
Only the completed ZIP is saved by the operator client after hash verification.

The extension rejects cache, resume, credential-file, and ccache modes in its
diskless API. The ordinary RustHound CLI retains its existing file output and
cache behavior. Windows amd64 is the verified Armory target; other RustHound
CLI targets are unaffected.

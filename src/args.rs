//! Parsing arguments
#[cfg(not(feature = "noargs"))]
use clap::{Arg, ArgAction, value_parser, Command};

#[derive(Clone, Debug)]
pub struct Options {
    pub domain: String,
    /// Authenticate with the logged-in Windows user's network credentials.
    pub current_user: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ldapfqdn: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub name_server: String,
    pub path: String,
    pub collection_method: CollectionMethod,
    pub ldaps: bool,
    pub dns_tcp: bool,
    pub fqdn_resolver: bool,
    pub hashes: Option<String>,
    pub kerberos: bool,
    // Certificate authentication (Pass-the-Certificate / Schannel)
    pub pfx: Option<String>,
    pub pfx_pass: Option<String>,
    pub crt: Option<String>,
    pub key: Option<String>,
    pub zip: bool,
    pub verbose: log::LevelFilter,
    pub ldap_filter: String,

    pub cache: bool,
    pub cache_buffer_size: usize,
    pub resume: bool,
}

impl Options {
    /// True when authenticating with a client certificate (no SMB credentials
    /// are available, so SMB-based modules must be skipped).
    pub fn uses_cert(&self) -> bool {
        self.pfx.is_some() || self.crt.is_some()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CollectionMethod {
    All,            // LDAP + Session (all three RPC paths) + SMB on SYSVOL + LocalGroup 
    DCOnly,         // LDAP only, never contacts a machine + SMB on SYSVOL
    Session,        // LDAP + SRVSVC + WKSSVC + WINREG 
    RegistryOnly,   // LDAP + WINREG
    LdapOnly,       // LDAP
    GPOLocalGroup,  // LDAP + GPOLocalGroup with SMB on SYSVOL
    LocalGroup,     // LDAP + RPC SAMR
    WebClient,      // LDAP + SMB WebDAV pipe probe (IsWebClientRunning)
    CARegistry      // LDAP + MS-RRP \winreg CA registry values (CARegistryData)
}

impl CollectionMethod {
    pub fn does_session(&self)      -> bool { self.srvsvc() || self.wkssvc() || self.registry() }
    pub fn srvsvc(&self)            -> bool { matches!(self, Self::All | Self::Session) }
    pub fn wkssvc(&self)            -> bool { matches!(self, Self::All | Self::Session) }
    pub fn registry(&self)          -> bool { matches!(self, Self::All | Self::Session | Self::RegistryOnly) }
    pub fn does_gpo(&self)          -> bool { matches!(self, Self::All | Self::DCOnly | Self::GPOLocalGroup) }
    pub fn does_local_group(&self)  -> bool { matches!(self, Self::All | Self::LocalGroup) }
    pub fn does_web_client(&self)   -> bool { matches!(self, Self::All | Self::WebClient) }
    pub fn does_ca_registry(&self)  -> bool { matches!(self, Self::All | Self::CARegistry) }
}

// Current RustHound version
pub const RUSTHOUND_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(not(feature = "noargs"))]
fn cli() -> Command {
    // Return Command args
    Command::new("rusthound-ce")
    .version(RUSTHOUND_VERSION)
    .about("Active Directory data collector for BloodHound Community Edition.\ng0h4n <https://twitter.com/g0h4n_0>")
    .arg(Arg::new("v")
        .short('v')
        .help("Set the level of verbosity")
        .action(ArgAction::Count),
    )
    .next_help_heading("REQUIRED VALUES")
    .arg(Arg::new("domain")
        .short('d')
        .long("domain")
            .help("Domain name like: DOMAIN.LOCAL")
            .required_unless_present("current-user")
            .value_parser(value_parser!(String))
    )
    .next_help_heading("OPTIONAL VALUES")
    .arg(Arg::new("ldapusername")
        .short('u')
        .long("ldapusername")
        .help("LDAP username, like: user@domain.local")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldappassword")
        .short('p')
        .long("ldappassword")
        .help("LDAP password")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("hashes")
        .short('H')
        .long("hashes")
        .help("NT hash for pass-the-hash authentication (NTLM), accept [NTHASH, :NTHASH, LMHASH:NTHASH]")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldapfqdn")
        .short('f')
        .long("ldapfqdn")
        .help("Domain Controller FQDN like: DC01.DOMAIN.LOCAL or just DC01")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldapip")
        .short('i')
        .long("ldapip")
        .help("Domain Controller IP address like: 192.168.1.10")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("ldapport")
        .short('P')
        .long("ldapport")
        .help("LDAP port [default: 389, or 636 with --ldaps]")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("name-server")
        .short('n')
        .long("name-server")
        .help("Alternative IP address name server to use for DNS queries")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("output")
        .short('o')
        .long("output")
        .help("Output directory where you would like to save JSON files [default: ./]")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .next_help_heading("CERTIFICATE AUTHENTICATION")
    .arg(Arg::new("pfx")
        .long("pfx")
        .help("PFX/PKCS#12 client certificate for certificate authentication (Pass-the-Certificate). Uses StartTLS by default, or LDAPS with --ldaps")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("pfx-pass")
        .long("pfx-pass")
        .help("Password protecting the PFX file (optional)")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("crt")
        .long("crt")
        .help("PEM client certificate for certificate authentication (use with --key)")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .arg(Arg::new("key")
        .long("key")
        .help("PEM private key for certificate authentication (use with --crt)")
        .required(false)
        .value_parser(value_parser!(String))
    )
    .next_help_heading("OPTIONAL FLAGS")
    .arg(Arg::new("current-user")
        .long("current-user")
        .help("Windows only: use the logged-in domain user's credentials and discover the domain/DC automatically")
        .action(ArgAction::SetTrue)
        .conflicts_with_all(["ldapusername", "ldappassword", "hashes", "kerberos", "pfx", "pfx-pass", "crt", "key"])
    )
    .arg(Arg::new("collectionmethod")
        .short('c')
        .long("collectionmethod")
        .help("Which information to collect. Supported: All (LDAP, SMB, HTTP), DCOnly (LDAP + SYSVOL, no member-machine connections), Session (user sessions over RPC), RegistryOnly (sessions over WINREG), LdapOnly (LDAP only, no machine or SYSVOL), GPOLocalGroup (LDAP + SMB SYSVOL for read local group member over GPO), LocalGroup (LDAP + SAMR BUILTIN alias membership), WebClient (LDAP + SMB WebDAV pipe probe for IsWebClientRunning), CARegistry (LDAP + MS-RRP winreg for the CA registry values IsUserSpecifiesSanEnabled and RoleSeparationEnabled) (default: All)")
        .value_name("COLLECTIONMETHOD")
        .value_parser(["All", "DCOnly", "Session", "RegistryOnly", "LdapOnly", "GPOLocalGroup", "LocalGroup", "WebClient", "CARegistry"])
        .num_args(0..=1)
        .default_missing_value("All")
    )
    .arg(Arg::new("ldap-filter")
        .long("ldap-filter")
        .help("Use custom ldap-filter default is : (objectClass=*)")
        .required(false)
        .value_parser(value_parser!(String))
        .default_missing_value("(objectClass=*)")
    )
    .arg(Arg::new("ldaps")
        .long("ldaps")
        .help("Force LDAPS using for request like: ldaps://DOMAIN.LOCAL/")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("kerberos")
        .short('k')
        .long("kerberos")
        .help("Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters for Linux.")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("dns-tcp")
        .long("dns-tcp")
        .help("Use TCP instead of UDP for DNS queries")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("zip")
        .long("zip")
        .short('z')
        .help("Compress the JSON files into a zip archive")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
    .arg(Arg::new("cache")
        .long("cache")
        .help("Cache LDAP search results to disk (reduce memory usage on large domains)")
        .required(false)
        .action(ArgAction::SetTrue)
    )
    .arg(Arg::new("cache_buffer")
        .long("cache-buffer")
        .help("Buffer size to use when caching")
        .required(false)
        .value_parser(value_parser!(usize))
        .default_value("1000")
    )
    .arg(Arg::new("resume")
        .long("resume")
        .help("Resume the collection from the last saved state")
        .required(false)
        .action(ArgAction::SetTrue)
    )
    .next_help_heading("OPTIONAL MODULES")
    .arg(Arg::new("fqdn-resolver")
        .long("fqdn-resolver")
        .help("Use fqdn-resolver module to get computers IP address")
        .required(false)
        .action(ArgAction::SetTrue)
        .global(false)
    )
}

#[cfg(not(feature = "noargs"))]
/// Function to extract all argument and put it in 'Options' structure.
pub fn extract_args() -> Options {

    // Get arguments
    #[cfg(windows)]
    let matches = {
        let mut argv: Vec<_> = std::env::args_os().collect();
        if argv.len() == 1 {
            argv.push("--current-user".into());
        }
        cli().get_matches_from(argv)
    };
    #[cfg(not(windows))]
    let matches = cli().get_matches();

    // Now get values
    let current_user = matches.get_flag("current-user");
    #[allow(unused_mut)]
    let mut domain = matches.get_one::<String>("domain").cloned().unwrap_or_default();
    #[allow(unused_mut)]
    let mut discovered_dc = None;
    if current_user {
        #[cfg(windows)]
        {
            let discovered = crate::transport::windows_domain::discover_domain_controller(
                if domain.is_empty() { None } else { Some(&domain) },
            ).unwrap_or_else(|e| cli().error(clap::error::ErrorKind::InvalidValue, e).exit());
            if domain.is_empty() {
                domain = discovered.domain;
            }
            discovered_dc = Some(discovered.dc_fqdn);
        }
        #[cfg(not(windows))]
        cli().error(clap::error::ErrorKind::InvalidValue,
            "--current-user requires a Windows build").exit();
    }
    let username = matches
        .get_one::<String>("ldapusername")
        .map(|s| s.to_owned());
    let password = matches
        .get_one::<String>("ldappassword")
        .map(|s| s.to_owned());
    let hashes = matches
        .get_one::<String>("hashes")
        .map(|s| s.to_owned());
    let f = matches.get_one::<String>("ldapfqdn").cloned().or(discovered_dc);
    let ip = matches.get_one::<String>("ldapip").cloned();    
    let port = match matches.get_one::<String>("ldapport") {
        Some(val) => val.parse::<u16>().ok(),
        None => None,
    };
    let n = matches
        .get_one::<String>("name-server")
        .map(|s| s.as_str())
        .unwrap_or("not set");
    let path = matches
        .get_one::<String>("output")
        .map(|s| s.as_str())
        .unwrap_or("./");
    let ldaps = matches
        .get_one::<bool>("ldaps")
        .map(|s| s.to_owned())
        .unwrap_or(false);
    let dns_tcp = matches
        .get_one::<bool>("dns-tcp")
        .map(|s| s.to_owned())
        .unwrap_or(false);
    let z = matches
        .get_one::<bool>("zip")
        .map(|s| s.to_owned())
        .unwrap_or(false);
    let fqdn_resolver = matches
        .get_one::<bool>("fqdn-resolver")
        .map(|s| s.to_owned())
        .unwrap_or(false);
    let kerberos = matches
        .get_one::<bool>("kerberos")
        .map(|s| s.to_owned())
        .unwrap_or(false);

    // Certificate authentication paths
    let pfx = matches.get_one::<String>("pfx").cloned();
    let pfx_pass = matches.get_one::<String>("pfx-pass").cloned();
    let crt = matches.get_one::<String>("crt").cloned();
    let key = matches.get_one::<String>("key").cloned();

    let v = match matches.get_count("v") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    let collection_method = match matches
        .get_one::<String>("collectionmethod")
        .map(|s| s.as_str())
        .unwrap_or("All")
    {
        "All"           => CollectionMethod::All,
        "DCOnly"        => CollectionMethod::DCOnly,
        "Session"       => CollectionMethod::Session,
        "RegistryOnly"  => CollectionMethod::RegistryOnly,
        "LdapOnly"      => CollectionMethod::LdapOnly,
        "GPOLocalGroup" => CollectionMethod::GPOLocalGroup,
        "LocalGroup"    => CollectionMethod::LocalGroup,
        "WebClient"     => CollectionMethod::WebClient,
        "CARegistry"    => CollectionMethod::CARegistry,
        _               => CollectionMethod::All,
    };
    let ldap_filter = matches.get_one::<String>("ldap-filter").map(|s| s.as_str()).unwrap_or("(objectClass=*)");

    let cache = matches.get_flag("cache");
    let cache_buffer_size = matches
        .get_one::<usize>("cache_buffer")
        .copied()
        .unwrap_or(1000);
    let resume = matches.get_flag("resume");

    // Return all
    Options {
        domain,
        current_user,
        username,
        password,
        hashes,
        ldapfqdn: f,
        ip,
        port,
        name_server: n.to_string(),
        path: path.to_string(),
        collection_method,
        ldaps,
        dns_tcp,
        fqdn_resolver,
        kerberos,
        pfx,
        pfx_pass,
        crt,
        key,
        zip: z,
        verbose: v,
        ldap_filter: ldap_filter.to_string(),
        cache,
        cache_buffer_size,
        resume,
    }
}

#[cfg(feature = "noargs")]
/// Function to automatically get all informations needed and put it in 'Options' structure.
pub fn auto_args() -> Options {
    let discovered = crate::transport::windows_domain::discover_domain_controller(None)
        .expect("could not discover the joined Windows domain and DC");

    // Return all
    Options {
        domain: discovered.domain,
        current_user: true,
        username: None,
        password: None,
        ldapfqdn: Some(discovered.dc_fqdn),
        ip: None, 
        port: None,
        name_server: "127.0.0.1".to_string(),
        path: "./output".to_string(),
        collection_method: CollectionMethod::All,
        ldaps: false,
        dns_tcp: false,
        fqdn_resolver: false,
        hashes: None,
        kerberos: false,
        pfx: None,
        pfx_pass: None,
        crt: None,
        key: None,
        zip: true,
        verbose: log::LevelFilter::Info,
        ldap_filter: "(objectClass=*)".to_string(),
        cache: false,
        cache_buffer_size: 1000,
        resume: false,
    }
}

#[cfg(test)]
mod tests {
    use super::CollectionMethod::*;

    #[cfg(not(feature = "noargs"))]
    #[test]
    fn current_user_cli_accepts_discovery_and_rejects_explicit_credentials() {
        assert!(super::cli().try_get_matches_from(["rusthound-ce", "--current-user"]).is_ok());
        assert!(super::cli().try_get_matches_from(["rusthound-ce", "-d", "example.local"]).is_ok());
        assert!(super::cli().try_get_matches_from(["rusthound-ce"]).is_err());
        assert!(super::cli().try_get_matches_from([
            "rusthound-ce", "--current-user", "--ldappassword", "secret",
        ]).is_err());
    }

    #[test]
    fn session_module_runs_for_every_method_that_makes_a_session_call() {
        // (method, srvsvc, wkssvc, registry, session module runs)
        let table = [
            (All,           true,  true,  true,  true),
            (Session,       true,  true,  true,  true),
            (RegistryOnly,  false, false, true,  true),
            (DCOnly,        false, false, false, false),
            (LdapOnly,      false, false, false, false),
            (GPOLocalGroup, false, false, false, false),
            (LocalGroup,    false, false, false, false),
            (WebClient,     false, false, false, false),
            (CARegistry,    false, false, false, false),
        ];
        for (method, srvsvc, wkssvc, registry, session) in table {
            assert_eq!(
                (method.srvsvc(), method.wkssvc(), method.registry(), method.does_session()),
                (srvsvc, wkssvc, registry, session),
                "{method:?}"
            );
        }
    }
}

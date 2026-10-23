pub mod banner;

// Scalable multithreaded allocator. The default OS allocator (the Windows
// process heap in particular) serializes concurrent allocations behind a lock,
// which throttled every parallel phase — decode, parse, and the checker all
// allocate heavily, so threads spent their time contending instead of working.
// mimalloc uses per-thread heaps and removes that bottleneck.pub mod banner;
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use env_logger::Builder;
use log::{error, info, trace};

use rusthound_ce::{args, ldap_auth, api::run_collection, utils};
use std::error::Error;
use std::time::Duration;

#[cfg(feature = "noargs")]
use args::auto_args;
#[cfg(not(feature = "noargs"))]
use args::{extract_args, Options};

use banner::{print_banner, print_end_banner};

/// Main of RustHound
fn main() -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run());
    // RegConnectRegistryW is a blocking Win32 call. A timed-out remote
    // registry request may still be running on Tokio's blocking pool, so do
    // not let it keep the CLI process alive indefinitely after collection.
    runtime.shutdown_timeout(Duration::from_secs(5));
    result
}

async fn run() -> Result<(), Box<dyn Error>> {
    // Banner
    print_banner();

    // Get args
    #[cfg(not(feature = "noargs"))]
    let common_args: Options = extract_args();
    #[cfg(feature = "noargs")]
    let common_args = auto_args();

    // Build logger
    Builder::new()
        .filter(Some("rusthound"), common_args.verbose)
        .filter_level(log::LevelFilter::Error)
        .init();

    info!("Verbosity level: {:?}", common_args.verbose);
    info!("Collection method: {:?}", common_args.collection_method);

    // 1) Authenticate to the Domain Controller.
    let mut ldap = ldap_auth(&common_args).await?;

    // 2) Run the full workflow (collect -> parse -> modules -> JSON/zip).
    let result = run_collection(&mut ldap, &common_args).await;

    // Close the session.
    let _ = ldap.unbind().await;

    match result {
        Ok(out) => trace!("Output written to {out}"),
        Err(err) => {
            error!("Collection failed. Reason: {err}");
            return Err(err);
        }
    }

    // End banner
    print_end_banner();
    Ok(())
}

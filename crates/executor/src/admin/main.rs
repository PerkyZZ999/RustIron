//! Administration helper: binds its fixed socket and reads request lines
//! concurrently (bounded, W186) and decides and acts on them one at a time. Every decision is [`admin_helper::Helper`].
//!
//! It refuses to start unless it runs in `rustiron_admin_t`: a failed domain
//! transition (missing module, wrong label) must not leave an unconfined
//! process serving administrative steps. It then serves only peers in
//! `rustiron_executor_t`.
use std::{path::Path, process::ExitCode};

use rustiron_executor::{TrustAnchor, admin_helper, serve};

fn boot_restore(anchor: &TrustAnchor) -> ExitCode {
    let outcome = admin_helper::boot_restore_ejected_php(anchor);
    let report = match &outcome {
        Ok(admin_helper::BootRestoreOutcome::Restored(operation, site)) => serde_json::json!({
            "result": "ready", "operation_id": operation.as_str(), "site_id": site.as_str()
        }),
        Ok(admin_helper::BootRestoreOutcome::NoPendingEject) => {
            serde_json::json!({"result": "no_pending_eject"})
        }
        Ok(admin_helper::BootRestoreOutcome::SkippedExecutorActive) => {
            serde_json::json!({"result": "skipped_executor_active"})
        }
        Err(error) => serde_json::json!({"result": "failed", "error": error.code()}),
    };
    println!(
        "{}",
        serde_json::json!({"scope": "ols_boot_php_restore", "outcome": report})
    );
    if outcome.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn main() -> ExitCode {
    let own = admin_helper::process_type("self");
    if own.as_deref() != Some(admin_helper::LAB_HELPER_TYPE) {
        eprintln!("{{\"error\":\"ADMIN_HELPER_DOMAIN\"}}");
        return ExitCode::from(3);
    }
    let anchor = TrustAnchor::host();
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [command] if command == "boot-restore-ejected-php" => return boot_restore(&anchor),
        [] => {}
        _ => {
            eprintln!("{{\"error\":\"INVALID_REQUEST\"}}");
            return ExitCode::from(2);
        }
    }
    let Ok(listener) = serve::bind(Path::new(admin_helper::LAB_SOCKET), anchor.owner_uid) else {
        eprintln!("{{\"error\":\"ADMIN_HELPER_BIND\"}}");
        return ExitCode::from(2);
    };
    let mut helper =
        admin_helper::Helper::new(anchor, Some(admin_helper::LAB_EXECUTOR_TYPE.to_owned()));
    match admin_helper::serve_helper(&mut helper, &listener, admin_helper::MAX_PENDING_READS) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(2),
    }
}

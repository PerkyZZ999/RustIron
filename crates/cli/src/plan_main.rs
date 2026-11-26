//! `rustiron-plan inspect PLAN.json`: decode one closed operation plan offline and
//! show exactly what it asks for, for the human reviewing it before signing.
//! `rustiron-plan migrate OBSERVATION DECLARATION TARGET [OPTIONS]`: the offline
//! P01 migration dry run (W456, W591).
//! No signing, admission, network or execution; the plan is untrusted input
//! and every displayed value has passed the closed contract decoders.

mod file_input;
mod migration_plan;
mod plan_summary;

use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

use rustiron_contracts::{MAX_REQUEST_BYTES, escape_human};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("migrate") {
        return migrate(&args[1..]);
    }
    let [command, path] = args.as_slice() else {
        return fail();
    };
    if command == "envelope" {
        return envelope(path);
    }
    if command != "inspect" {
        return fail();
    }
    let Ok(bytes) = file_input::read(Path::new(path), MAX_REQUEST_BYTES) else {
        return fail();
    };
    let Some((verb, digest, lines)) = plan_summary::describe(&bytes) else {
        return fail();
    };
    let mut text = format!("verb: {verb}\nplan digest: {digest}\n");
    for (label, value) in lines {
        text.push_str(&format!("{label}: {}\n", escape_human(&value)));
    }
    text.push_str("authority: none (review only; signing happens elsewhere)\n");
    match io::stdout().lock().write_all(text.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(7),
    }
}

/// Exit 0 with the dry run, 2 on invalid input, 3 with every refusal,
/// 4 on declaration signature denial, or 7 on verifier/output failure.
fn migrate(args: &[String]) -> ExitCode {
    let Some((observation, declaration, target, parsed)) = parse_migrate_args(args) else {
        return migrate_error(
            b"{\"scope\":\"migration_plan\",\"error\":\"INVALID_MIGRATION_INPUT\"}\n",
            2,
        );
    };
    let options = migration_plan::Options {
        target_observation: parsed.target_observation.map(Path::new),
        signature: parsed
            .signature
            .map(|sig| migration_plan::DeclarationSignature {
                signature: Path::new(sig.signature),
                allowed_signers: Path::new(sig.allowed_signers),
                principal: sig.principal,
                revocations: sig.revocations.map(Path::new),
            }),
    };
    let outcome = migration_plan::run(
        Path::new(observation),
        Path::new(declaration),
        Path::new(target),
        &options,
    );
    let (text, code) = match outcome {
        migration_plan::Outcome::Plan(text) => (text, ExitCode::SUCCESS),
        migration_plan::Outcome::Refused(json) => (json + "\n", ExitCode::from(3)),
        migration_plan::Outcome::InvalidInput => {
            return migrate_error(
                b"{\"scope\":\"migration_plan\",\"error\":\"INVALID_MIGRATION_INPUT\"}\n",
                2,
            );
        }
        migration_plan::Outcome::SignatureDenied => {
            return migrate_error(
                b"{\"scope\":\"migration_plan\",\"error\":\"DECLARATION_SIGNATURE_DENIED\"}\n",
                4,
            );
        }
        migration_plan::Outcome::DependencyUnavailable => {
            return migrate_error(
                b"{\"scope\":\"migration_plan\",\"error\":\"MIGRATION_DEPENDENCY_UNAVAILABLE\"}\n",
                7,
            );
        }
    };
    match io::stdout().lock().write_all(text.as_bytes()) {
        Ok(()) => code,
        Err(_) => ExitCode::from(7),
    }
}

struct ParsedSignature<'a> {
    signature: &'a str,
    allowed_signers: &'a str,
    principal: &'a str,
    revocations: Option<&'a str>,
}

struct ParsedMigrate<'a> {
    target_observation: Option<&'a str>,
    signature: Option<ParsedSignature<'a>>,
}

fn parse_migrate_args<'a>(
    args: &'a [String],
) -> Option<(&'a str, &'a str, &'a str, ParsedMigrate<'a>)> {
    if args.len() < 3 {
        return None;
    }
    let observation = args[0].as_str();
    let declaration = args[1].as_str();
    let target = args[2].as_str();
    if observation.starts_with("--") || declaration.starts_with("--") || target.starts_with("--") {
        return None;
    }
    let mut target_observation: Option<&'a str> = None;
    let mut declaration_sig: Option<&'a str> = None;
    let mut allowed_signers: Option<&'a str> = None;
    let mut principal: Option<&'a str> = None;
    let mut revocations: Option<&'a str> = None;

    let mut index = 3;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args.get(index + 1)?.as_str();
        match flag {
            "--target-observation" => {
                if target_observation.replace(value).is_some() {
                    return None;
                }
            }
            "--declaration-sig" => {
                if declaration_sig.replace(value).is_some() {
                    return None;
                }
            }
            "--allowed-signers" => {
                if allowed_signers.replace(value).is_some() {
                    return None;
                }
            }
            "--principal" => {
                if principal.replace(value).is_some() {
                    return None;
                }
            }
            "--revocations" => {
                if revocations.replace(value).is_some() {
                    return None;
                }
            }
            _ => return None,
        }
        index += 2;
    }

    let any_sig = declaration_sig.is_some()
        || allowed_signers.is_some()
        || principal.is_some()
        || revocations.is_some();
    let signature = if any_sig {
        Some(ParsedSignature {
            signature: declaration_sig?,
            allowed_signers: allowed_signers?,
            principal: principal?,
            revocations,
        })
    } else {
        None
    };

    Some((
        observation,
        declaration,
        target,
        ParsedMigrate {
            target_observation,
            signature,
        },
    ))
}

fn migrate_error(body: &[u8], code: u8) -> ExitCode {
    let _ = io::stdout().lock().write_all(body);
    ExitCode::from(code)
}

/// Fixed output; the input is never echoed.
fn fail() -> ExitCode {
    let _ = io::stdout()
        .lock()
        .write_all(b"{\"scope\":\"plan_inspect\",\"error\":\"INVALID_PLAN_INPUT\"}\n");
    ExitCode::from(2)
}

/// P23 (D-098): emit the closed JSON blast-radius envelope of one plan offline.
fn envelope(path: &str) -> ExitCode {
    let Ok(bytes) = file_input::read(Path::new(path), MAX_REQUEST_BYTES) else {
        return fail();
    };
    let Some(env) = rustiron_contracts::approval::envelope_for_plan(&bytes) else {
        return fail();
    };
    let Ok(mut json) = serde_json::to_string(&env) else {
        return fail();
    };
    json.push('\n');
    match io::stdout().lock().write_all(json.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(7),
    }
}

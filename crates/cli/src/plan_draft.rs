//! W780 (v0.3 item 50): unsigned plan drafts for `rustiron-mcp`, built by the
//! same `plan create` code as the CLI. A draft holds no authority: nothing is
//! signed, stored, or submitted, and the host is not observed.

use clap::{CommandFactory, Parser};
use serde_json::{Map, Value};

use crate::plan_create::{self, CreateCommand};

/// Verbs that read a file on this machine stay CLI-only.
const FILE_VERBS: [&str; 2] = ["dns-zone-import", "dns-change"];
/// Flag names clap handles itself, refused as draft input.
const RESERVED: [&str; 2] = ["help", "version"];
const MAX_FLAGS: usize = 64;
const MAX_VALUES: usize = 256;

#[derive(Parser)]
#[command(name = "rustiron plan create", disable_help_subcommand = true)]
struct Draft {
    #[command(subcommand)]
    command: CreateCommand,
}

/// A refused draft: a fixed code and a message for the agent.
#[derive(Debug)]
pub(crate) struct Refused {
    pub code: &'static str,
    pub message: String,
}

fn refused(code: &'static str, message: impl Into<String>) -> Refused {
    Refused {
        code,
        message: message.into(),
    }
}

/// The verbs a draft may use, in the CLI's order.
pub(crate) fn verbs() -> Vec<String> {
    Draft::command()
        .get_subcommands()
        .map(|command| command.get_name().to_owned())
        .filter(|name| !FILE_VERBS.contains(&name.as_str()))
        .collect()
}

/// The CLI help of one verb, or the verb list.
pub(crate) fn help(verb: Option<&str>) -> Result<String, Refused> {
    let mut command = Draft::command();
    let Some(verb) = verb else {
        return Ok(format!(
            "Verbs: {}. Ask for one verb's flags with its name.",
            verbs().join(", ")
        ));
    };
    if !verbs().iter().any(|name| name == verb) {
        return Err(refused(
            "UNKNOWN_OR_FILE_VERB",
            "Not a verb a draft may use.",
        ));
    }
    let subcommand = command
        .find_subcommand_mut(verb)
        .ok_or_else(|| refused("UNKNOWN_OR_FILE_VERB", "Not a verb a draft may use."))?;
    Ok(subcommand.render_long_help().to_string())
}

fn flag_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !RESERVED.contains(&name)
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.contains('\0') => Some(text.clone()),
        Value::Number(number) if number.is_u64() => Some(number.to_string()),
        _ => None,
    }
}

/// The argument vector for one verb. Every value is bound to its flag as
/// `--name=value`, so a value never becomes a flag or a positional argument.
pub(crate) fn argv(verb: &str, flags: &Map<String, Value>) -> Result<Vec<String>, Refused> {
    if !verbs().iter().any(|name| name == verb) {
        return Err(refused(
            "UNKNOWN_OR_FILE_VERB",
            "Not a verb a draft may use.",
        ));
    }
    if flags.len() > MAX_FLAGS {
        return Err(refused("INVALID_PLAN_FLAGS", "Too many flags."));
    }
    let mut argv = vec!["rustiron plan create".to_owned(), verb.to_owned()];
    let mut values = 0;
    for (name, value) in flags {
        if !flag_name(name) {
            return Err(refused(
                "INVALID_PLAN_FLAGS",
                "A flag name is not a plain CLI flag.",
            ));
        }
        let items: Vec<&Value> = match value {
            Value::Array(items) => items.iter().collect(),
            Value::Bool(true) => {
                argv.push(format!("--{name}"));
                continue;
            }
            other => vec![other],
        };
        for item in items {
            values += 1;
            let text = scalar(item).ok_or_else(|| {
                refused(
                    "INVALID_PLAN_FLAGS",
                    "A flag value must be a string or a whole number.",
                )
            })?;
            argv.push(format!("--{name}={text}"));
        }
    }
    if values > MAX_VALUES {
        return Err(refused("INVALID_PLAN_FLAGS", "Too many flag values."));
    }
    Ok(argv)
}

/// Builds one canonical unsigned plan, or says why not.
pub(crate) fn draft(verb: &str, flags: &Map<String, Value>) -> Result<Vec<u8>, Refused> {
    let argv = argv(verb, flags)?;
    let parsed = Draft::try_parse_from(argv)
        .map_err(|error| refused("INVALID_PLAN_FLAGS", error.render().to_string()))?;
    let captured = plan_create::capture(parsed.command);
    captured.plan.ok_or_else(|| {
        refused(
            "PLAN_REFUSED",
            captured
                .diagnostic
                .unwrap_or_else(|| "The plan did not validate.".to_owned()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{argv, draft, help, verbs};
    use serde_json::{Map, Value, json};

    fn flags(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn provision() -> Map<String, Value> {
        flags(json!({
            "plan-id": "plan_draft_1", "host-id": "host_lab", "host-epoch": "epoch_1",
            "profile-digest": "a".repeat(64), "requester": "agent_1",
            "site-id": "blog7", "hostname": "blog7.example.test",
            "recipe": "wordpress713_v1", "recipe-digest": "d".repeat(64),
            "observed-at": 990, "valid-from": 1000, "expires-at": 2000,
            "limitation": ["SYNTHETIC draft fixture"],
        }))
    }

    #[test]
    fn a_draft_is_the_cli_plan_and_file_verbs_are_cli_only() {
        assert!(verbs().contains(&"site-provision".to_owned()));
        assert!(!verbs().iter().any(|verb| verb.starts_with("dns-")));
        let plan = draft("site-provision", &provision()).unwrap();
        let text = String::from_utf8(plan).unwrap();
        assert!(text.contains("\"verb\":\"site_provision\""));
        assert!(text.contains("blog7.example.test"));
        assert_eq!(
            draft("dns-change", &provision()).unwrap_err().code,
            "UNKNOWN_OR_FILE_VERB"
        );
        assert!(help(Some("site-provision")).unwrap().contains("--hostname"));
    }

    #[test]
    fn values_cannot_become_flags_and_bad_input_is_refused() {
        // A value that looks like a flag stays the value of its own flag.
        let mut sneaky = provision();
        sneaky.insert("hostname".into(), json!("--site-id=evil"));
        let built = argv("site-provision", &sneaky).unwrap();
        assert!(built.contains(&"--hostname=--site-id=evil".to_owned()));
        assert_eq!(
            draft("site-provision", &sneaky).unwrap_err().code,
            "PLAN_REFUSED"
        );
        for (name, value) in [
            ("help", json!(true)),
            ("Site-Id", json!("x")),
            ("site id", json!("x")),
            ("site-id", json!(-1)),
            ("site-id", json!({"a": 1})),
            ("site-id", json!("a\u{0}b")),
        ] {
            let mut bad = provision();
            bad.insert(name.into(), value);
            assert!(draft("site-provision", &bad).is_err(), "{name}");
        }
        let mut unknown = provision();
        unknown.insert("grant".into(), json!("x"));
        assert_eq!(
            draft("site-provision", &unknown).unwrap_err().code,
            "INVALID_PLAN_FLAGS"
        );
    }
}

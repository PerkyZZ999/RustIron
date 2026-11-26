//! Read-only package pins for `observe` (W196): one fixed `rpm -q` query for
//! the hosting-profile packages. Reports name, exact EVR/arch and the RPM
//! signing key ID, or "not installed"; anything else is refused, and a
//! failed query leaves the field absent so the console labels it missing.
//!
//! W364: the product executor never runs the query. Its SELinux domain may
//! not execute `rpm` (W358, W361: one AVC for each `observe`), and the
//! smallest sound fix grants it nothing. The observation reports the package
//! facts as not observed ([`SOURCE`]). Preflight and the installer check the
//! required packages and the job tool pins as root before installation.

use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const RPM: &str = "/usr/bin/rpm";
/// The packages the lab hosting profile depends on.
pub(crate) const PACKAGES: [&str; 5] = [
    "almalinux-release",
    "openlitespeed",
    "lsphp84",
    "mariadb-server",
    "restic",
];
const FORMAT: &str = "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\t%{SIGPGP:pgpsig}\\n";
const TIMEOUT: Duration = Duration::from_secs(5);
/// Where the observation's package facts come from: `rpm` in the lab build,
/// `not_observed` in the product build, which never starts the query.
pub(crate) const SOURCE: &str = if cfg!(rustiron_profile = "product") {
    "not_observed"
} else {
    "rpm"
};
const MAX_OUTPUT: u64 = 16 * 1024;

/// One observed package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pin {
    pub name: String,
    /// `epoch:version-release.arch`, or `None` when not installed.
    pub version: Option<String>,
    /// The RPM signature key ID, or `None` when the package is unsigned.
    pub signing_key: Option<String>,
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:+~-".contains(&b))
}

/// Parses the fixed query output; `None` unless every package is accounted
/// for exactly once in a recognised form.
pub(crate) fn parse(text: &str) -> Option<Vec<Pin>> {
    let mut pins = Vec::new();
    for line in text.lines() {
        if let Some(name) = line
            .strip_prefix("package ")
            .and_then(|rest| rest.strip_suffix(" is not installed"))
        {
            pins.push(Pin {
                name: name.to_owned(),
                version: None,
                signing_key: None,
            });
            continue;
        }
        let mut fields = line.split('\t');
        let (Some(name), Some(version), Some(signature), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return None;
        };
        if !token(version) {
            return None;
        }
        let signing_key = match signature {
            "(none)" => None,
            text => {
                let key = text.rsplit_once("Key ID ")?.1;
                if key.len() != 16 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                Some(key.to_owned())
            }
        };
        pins.push(Pin {
            name: name.to_owned(),
            version: Some(version.to_owned()),
            signing_key,
        });
    }
    let mut names: Vec<&str> = pins.iter().map(|pin| pin.name.as_str()).collect();
    names.sort_unstable();
    let mut wanted = PACKAGES.to_vec();
    wanted.sort_unstable();
    (names == wanted).then_some(pins)
}

/// Runs the fixed query; `None` on any failure, timeout or unexpected output,
/// and always `None` without a process in the product build ([`SOURCE`]).
pub(crate) fn query() -> Option<Vec<Pin>> {
    if cfg!(rustiron_profile = "product") {
        return None;
    }
    let mut child = Command::new(RPM)
        .args(["-q", "--qf", FORMAT])
        .args(PACKAGES)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let out = child.stdout.take()?;
    let reader = thread::spawn(move || {
        let mut text = String::new();
        out.take(MAX_OUTPUT).read_to_string(&mut text).map(|_| text)
    });
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match child.try_wait() {
            // rpm exits 1 when a package is missing; the parser decides.
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    parse(&reader.join().ok()?.ok()?)
}

/// The observation field: an array of pins, or `null` when not observed.
pub(crate) fn to_json(packages: Option<&[Pin]>) -> serde_json::Value {
    packages.map_or(serde_json::Value::Null, |pins| {
        pins.iter()
            .map(|pin| {
                serde_json::json!({
                    "name": pin.name, "version": pin.version, "signing_key": pin.signing_key,
                })
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAB: &str = "almalinux-release\t0:10.2-17.el10.x86_64\tRSA/SHA256, Tue May 19 03:50:45 2026, Key ID dee5c11cc2a1e572\n\
openlitespeed\t0:1.9.3-1.el10.x86_64\t(none)\n\
lsphp84\t0:8.4.27-1.el10.x86_64\t(none)\n\
mariadb-server\t3:10.11.18-1.el10_2.alma.2.x86_64\tRSA/SHA256, Sat Sep 19 07:04:14 2026, Key ID dee5c11cc2a1e572\n\
restic\t0:0.19.1-1.el10_2.x86_64\t(none)\n";

    #[test]
    #[cfg(not(rustiron_profile = "product"))]
    fn the_lab_build_queries_rpm() {
        assert_eq!(SOURCE, "rpm");
    }

    #[test]
    fn lab_output_yields_exact_pins_and_signing_keys() {
        let pins = parse(LAB).expect("lab output parses");
        assert_eq!(pins.len(), 5);
        assert_eq!(
            pins[3].version.as_deref(),
            Some("3:10.11.18-1.el10_2.alma.2.x86_64")
        );
        assert_eq!(pins[3].signing_key.as_deref(), Some("dee5c11cc2a1e572"));
        assert_eq!(pins[1].signing_key, None);
    }

    #[test]
    fn the_observation_field_is_null_when_not_observed() {
        assert!(to_json(None).is_null());
        let value = to_json(parse(LAB).as_deref());
        assert_eq!(value[0]["name"], "almalinux-release");
        assert_eq!(value[1]["signing_key"], serde_json::Value::Null);
        assert_eq!(value[3]["version"], "3:10.11.18-1.el10_2.alma.2.x86_64");
    }

    #[test]
    fn a_missing_package_is_reported_not_dropped() {
        let text = LAB.replace(
            "restic\t0:0.19.1-1.el10_2.x86_64\t(none)\n",
            "package restic is not installed\n",
        );
        let pins = parse(&text).expect("parses");
        assert_eq!(
            pins[4],
            Pin {
                name: "restic".into(),
                version: None,
                signing_key: None
            }
        );
    }

    #[test]
    fn unexpected_or_incomplete_output_is_refused() {
        assert_eq!(parse(""), None);
        assert_eq!(parse(&LAB.replace("restic", "nginx")), None);
        assert_eq!(parse(&format!("{LAB}restic\t0:1-1.x86_64\t(none)\n")), None);
        assert_eq!(
            parse(&LAB.replace("0:1.9.3-1.el10.x86_64", "1.9 3;rm")),
            None
        );
        assert_eq!(
            parse(&LAB.replace("Key ID dee5c11cc2a1e572\nopen", "Key ID zz\nopen")),
            None
        );
        assert_eq!(
            parse(&LAB.replace("(none)\nlsphp84", "(none)\textra\nlsphp84")),
            None
        );
    }
}

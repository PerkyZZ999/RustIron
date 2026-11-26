//! D-091 (W550): the enrolled `dns` policy section and the PowerDNS
//! configuration rendered from it ([DNS design](../../docs/technical/DNS.md)).
//!
//! The section is root-admin enrollment, like the OLS listener. Nothing in
//! it comes from a plan. The render is the whole `/etc/pdns/pdns.conf`: the
//! SQLite backend, the enrolled listen addresses, primary operation with
//! transfers and NOTIFY only to the enrolled secondaries, and PowerDNS's
//! HTTP API and web server off. No PowerDNS host effect is implemented yet;
//! the install and the transfer proof wait for the D-092 download.

use std::{collections::BTreeSet, net::IpAddr};

use rustiron_contracts::approval::Hostname;
use serde::Deserialize;

/// The PowerDNS SQLite database the rendered configuration names.
pub(crate) const PDNS_DATABASE: &str = "/var/lib/pdns/pdns.sqlite3";
/// W563: the account PowerDNS's package runs as; `pdnsutil` runs as it.
pub(crate) const PDNS_USER: &str = "pdns";
/// W563: PowerDNS's state folder, the only one `pdnsutil` may write.
pub(crate) const PDNS_STATE_DIR: &str = "/var/lib/pdns";

/// The SOA timers of every zone Rustiron creates or imports.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SoaTimers {
    /// Seconds between a secondary's checks of the serial.
    pub refresh: u32,
    /// Seconds before a secondary retries a failed check.
    pub retry: u32,
    /// Seconds after which a secondary stops answering without a check.
    pub expire: u32,
    /// Seconds a resolver may cache "no such name".
    pub negative_ttl: u32,
}

impl SoaTimers {
    /// Within the ranges of RFC 1912 section 2.2, with retry below refresh
    /// and expire above both.
    pub fn valid(&self) -> bool {
        (1_200..=86_400).contains(&self.refresh)
            && (300..self.refresh).contains(&self.retry)
            && (604_800..=2_419_200).contains(&self.expire)
            && (60..=86_400).contains(&self.negative_ttl)
    }
}

/// The enrolled PowerDNS facts (D-091).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DnsPolicy {
    /// The addresses PowerDNS answers on, port 53, UDP and TCP.
    pub listen: Vec<IpAddr>,
    /// The zones' name server host names; the first is the SOA primary.
    pub name_servers: Vec<Hostname>,
    /// The SOA mailbox, written as a host name.
    pub hostmaster: Hostname,
    /// The addresses that may transfer zones and receive NOTIFY.
    pub secondaries: Vec<IpAddr>,
    /// The name of the TSIG key that signs transfers. Its secret stays in
    /// PowerDNS's database.
    pub tsig_key: String,
    /// The SOA timers.
    pub soa: SoaTimers,
}

/// A usable unicast address: not unspecified, not multicast.
fn unicast(address: &IpAddr) -> bool {
    !address.is_unspecified() && !address.is_multicast()
}

fn distinct<T: Ord>(items: &[T]) -> bool {
    items.iter().collect::<BTreeSet<_>>().len() == items.len()
}

/// A TSIG key name: dot-separated lowercase labels of letters, digits, and
/// inner hyphens, at most 63 bytes in all.
fn tsig_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl DnsPolicy {
    /// One to four distinct listen addresses; two to four distinct name
    /// servers (RFC 2182 asks for at least two); at most eight distinct
    /// secondaries; a TSIG key name; and SOA timers in range.
    pub fn valid(&self) -> bool {
        (1..=4).contains(&self.listen.len())
            && distinct(&self.listen)
            && self.listen.iter().all(unicast)
            && (2..=4).contains(&self.name_servers.len())
            && distinct(
                &self
                    .name_servers
                    .iter()
                    .map(Hostname::as_str)
                    .collect::<Vec<_>>(),
            )
            && self.secondaries.len() <= 8
            && distinct(&self.secondaries)
            && self.secondaries.iter().all(unicast)
            && tsig_name(&self.tsig_key)
            && self.soa.valid()
    }

    /// The complete `pdns.conf`. Without secondaries, transfers are off and
    /// NOTIFY goes nowhere.
    pub fn render(&self) -> String {
        let join = |addresses: &[IpAddr]| {
            addresses
                .iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        let soa = &self.soa;
        let mut text = String::from(
            "# Rendered by Rustiron from the enrolled dns policy (D-091). Any change is drift.\n",
        );
        for line in [
            "launch=gsqlite3".to_owned(),
            format!("gsqlite3-database={PDNS_DATABASE}"),
            format!("local-address={}", join(&self.listen)),
            "local-port=53".to_owned(),
            "primary=yes".to_owned(),
            "secondary=no".to_owned(),
            "api=no".to_owned(),
            "webserver=no".to_owned(),
            "version-string=anonymous".to_owned(),
            // W560-F1: no security-status query to secpoll.powerdns.com at
            // start; PowerDNS releases are tracked by the support matrix (P06).
            "security-poll-suffix=".to_owned(),
            format!(
                "default-soa-content={} {} 0 {} {} {} {}",
                self.name_servers[0].as_str(),
                self.hostmaster.as_str(),
                soa.refresh,
                soa.retry,
                soa.expire,
                soa.negative_ttl
            ),
        ] {
            text.push_str(&line);
            text.push('\n');
        }
        if self.secondaries.is_empty() {
            text.push_str("disable-axfr=yes\nonly-notify=\n");
        } else {
            // W560-F2: `allow-axfr-ips` grants a transfer by address alone,
            // beside a zone's TSIG-ALLOW-AXFR key. Empty, only a transfer
            // signed with the zone's key passes.
            let secondaries = join(&self.secondaries);
            text.push_str(&format!(
                "disable-axfr=no\nallow-axfr-ips=\nalso-notify={secondaries}\nonly-notify={secondaries}\n"
            ));
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> DnsPolicy {
        serde_json::from_str(
            r#"{"listen":["203.0.113.10","2001:db8::10"],
                "name_servers":["ns1.example.test","ns2.example.test"],
                "hostmaster":"hostmaster.example.test",
                "secondaries":["198.51.100.53"],
                "tsig_key":"rustiron-axfr",
                "soa":{"refresh":10800,"retry":3600,"expire":604800,"negative_ttl":3600}}"#,
        )
        .unwrap()
    }

    #[test]
    fn the_enrolled_section_renders_the_whole_configuration() {
        let policy = policy();
        assert!(policy.valid());
        assert_eq!(
            policy.render(),
            "# Rendered by Rustiron from the enrolled dns policy (D-091). Any change is drift.\n\
             launch=gsqlite3\n\
             gsqlite3-database=/var/lib/pdns/pdns.sqlite3\n\
             local-address=203.0.113.10,2001:db8::10\n\
             local-port=53\n\
             primary=yes\n\
             secondary=no\n\
             api=no\n\
             webserver=no\n\
             version-string=anonymous\n\
             security-poll-suffix=\n\
             default-soa-content=ns1.example.test hostmaster.example.test 0 10800 3600 604800 3600\n\
             disable-axfr=no\n\
             allow-axfr-ips=\n\
             also-notify=198.51.100.53\n\
             only-notify=198.51.100.53\n"
        );
    }

    #[test]
    fn without_secondaries_transfers_and_notify_are_off() {
        let mut policy = policy();
        policy.secondaries.clear();
        assert!(policy.valid());
        let text = policy.render();
        assert!(text.ends_with("disable-axfr=yes\nonly-notify=\n"));
        assert!(!text.contains("allow-axfr-ips") && !text.contains("also-notify"));
    }

    #[test]
    fn each_bound_is_refused() {
        let refused = |change: &dyn Fn(&mut DnsPolicy)| {
            let mut policy = policy();
            change(&mut policy);
            assert!(!policy.valid());
        };
        refused(&|p| p.listen.clear());
        refused(&|p| p.listen.push("203.0.113.10".parse().unwrap()));
        refused(&|p| p.listen.push("0.0.0.0".parse().unwrap()));
        refused(&|p| p.listen.push("ff02::1".parse().unwrap()));
        refused(&|p| {
            p.name_servers.truncate(1);
        });
        refused(&|p| {
            p.name_servers[1] = p.name_servers[0].clone();
        });
        refused(&|p| {
            p.secondaries = (0..9u8)
                .map(|i| IpAddr::from([198, 51, 100, i + 1]))
                .collect()
        });
        refused(&|p| p.secondaries.push("198.51.100.53".parse().unwrap()));
        refused(&|p| p.secondaries.push("::".parse().unwrap()));
        for name in [
            "",
            "Upper",
            "-lead",
            "trail-",
            "a..b",
            "a b",
            "x\nallow-axfr-ips=0.0.0.0/0",
        ] {
            refused(&|p| p.tsig_key = name.to_owned());
        }
        refused(&|p| p.tsig_key = "a".repeat(64));
        refused(&|p| p.soa.refresh = 600);
        refused(&|p| p.soa.retry = p.soa.refresh);
        refused(&|p| p.soa.expire = 3_600);
        refused(&|p| p.soa.negative_ttl = 10);
    }

    #[test]
    fn unknown_fields_and_bad_names_do_not_decode() {
        assert!(
            serde_json::from_str::<DnsPolicy>(
                r#"{"listen":["203.0.113.10"],"name_servers":["ns1.example.test","ns2.example.test"],
                    "hostmaster":"hostmaster.example.test","secondaries":[],"tsig_key":"k",
                    "soa":{"refresh":10800,"retry":3600,"expire":604800,"negative_ttl":3600},
                    "api":"yes"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<DnsPolicy>(
                r#"{"listen":["203.0.113.10"],"name_servers":["NS1.example.test","ns2.example.test"],
                    "hostmaster":"hostmaster.example.test","secondaries":[],"tsig_key":"k",
                    "soa":{"refresh":10800,"retry":3600,"expire":604800,"negative_ttl":3600}}"#
            )
            .is_err()
        );
    }
}

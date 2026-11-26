//! W317/W352 (B01/B09): the store namespace script and units agree with the
//! compiled product layout and with the ruleset the executor requires.
use std::net::{Ipv4Addr, SocketAddrV4};

use rustiron_executor::{layout::product, store_network};

const SCRIPT: &str = include_str!("../../../packaging/store/rustiron-store-netns");
const NETNS_UNIT: &str = include_str!("../../../packaging/systemd/rustiron-store-netns.service");
const SOCKET: &str = include_str!("../../../packaging/systemd/rustiron-store-relay@.socket");
const RELAY: &str = include_str!("../../../packaging/systemd/rustiron-store-relay@.service");

fn values<'a>(unit: &'a str, key: &str) -> Vec<&'a str> {
    unit.lines()
        .filter_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .collect()
}

#[test]
fn units_name_the_compiled_namespace_and_endpoint_file() {
    let file = format!(
        "{}/{}",
        product::POLICY_DIR,
        store_network::STORE_NETWORK_FILE
    );
    assert_eq!(values(NETNS_UNIT, "EnvironmentFile"), [file.as_str()]);
    assert_eq!(values(RELAY, "EnvironmentFile"), [file.as_str()]);
    assert_eq!(
        values(SOCKET, "NetworkNamespacePath"),
        [product::STORE_NETNS]
    );
    let name = product::STORE_NETNS.rsplit('/').next().unwrap();
    assert!(SCRIPT.contains(&format!("\nnamespace={name}\n")));
    assert!(SCRIPT.contains("ip netns add \"$namespace\""));
}

#[test]
fn the_relay_listens_on_the_instance_port_and_forwards_to_the_enrolled_tuple() {
    let context = "system_u:system_r:rustiron_store_relay_t:s0";
    // W352: the instance name is the enrolled port; 443 is the default.
    assert_eq!(values(SOCKET, "ListenStream"), ["0.0.0.0:%i"]);
    assert_eq!(values(SOCKET, "DefaultInstance"), ["443"]);
    assert_eq!(values(SOCKET, "SELinuxContext"), [context]);
    assert_eq!(values(RELAY, "SELinuxContext"), [context]);
    // The relay connects only to the address and port of the endpoint
    // file, which the executor compares with the enrolled projection.
    assert_eq!(
        values(RELAY, "ExecStart"),
        [
            "/usr/lib/systemd/systemd-socket-proxyd --connections-max=8 ${RUSTIRON_STORE_ENDPOINT}:${RUSTIRON_STORE_PORT}"
        ]
    );
    assert_eq!(
        values(RELAY, "Requires"),
        ["rustiron-store-relay@%i.socket"]
    );
    assert_eq!(values(RELAY, "CapabilityBoundingSet"), [""]);
    assert_eq!(
        values(RELAY, "RestrictAddressFamilies"),
        ["AF_INET AF_UNIX"]
    );
    assert_eq!(values(SOCKET, "BindsTo"), ["rustiron-store-netns.service"]);
    assert_eq!(values(SOCKET, "PartOf"), ["rustiron-store-netns.service"]);
    // Default socket dependencies form a boot ordering cycle with the
    // namespace service (W317 first reboot).
    assert_eq!(values(SOCKET, "DefaultDependencies"), ["no"]);
    assert_eq!(values(SOCKET, "WantedBy"), ["multi-user.target"]);
    assert!(values(NETNS_UNIT, "Before").is_empty());
}

#[test]
fn the_script_loads_exactly_the_rules_the_executor_requires() {
    for endpoint in [
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 23), 443),
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 23), 9443),
    ] {
        let rules = |text: &str| -> Vec<String> {
            text.lines()
                .map(str::trim)
                .filter(|line| line.starts_with("ip ") || line.starts_with("type "))
                .map(|line| {
                    line.replace("$endpoint", "198.51.100.23")
                        .replace("$port", &endpoint.port().to_string())
                })
                .collect()
        };
        // The heredoc body the script feeds to nft, and nothing else.
        let body = SCRIPT
            .split_once("nft -f - <<NFT\n")
            .and_then(|(_, rest)| rest.split_once("\nNFT\n"))
            .map(|(body, _)| body)
            .unwrap();
        assert_eq!(SCRIPT.matches("<<NFT").count(), 1);
        assert_eq!(
            rules(body),
            rules(&store_network::expected_ruleset(endpoint))
        );
        assert_eq!(rules(body).len(), 3);
    }
}

#[test]
fn the_script_reads_the_two_lines_of_the_endpoint_file() {
    let endpoint = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 23), 9443);
    let file = store_network::expected_network_file(endpoint);
    for line in file.lines() {
        let (name, _) = line.split_once('=').unwrap();
        assert!(SCRIPT.contains(&format!("${{{name}:-}}")), "{name}");
    }
    assert_eq!(file.lines().count(), 2);
}

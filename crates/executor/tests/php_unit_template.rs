//! W231: a site pool that is repeatedly OOM-killed must not be left `failed`
//! by systemd's start limit (W227). Starts are request-driven (socket
//! activation, no `Restart=`), so the limit is disabled for the service.
const LAB: &str = include_str!("../../../lab/s03/rustiron-site-php@.service");
const PRODUCT: &str = include_str!("../../../packaging/systemd/rustiron-site-php@.service");

fn section(unit: &'static str, name: &str) -> Vec<&'static str> {
    let header = format!("[{name}]");
    unit.lines()
        .skip_while(|l| l.trim() != header)
        .skip(1)
        .take_while(|l| !l.starts_with('['))
        .map(str::trim)
        .collect()
}

#[test]
fn repeated_pool_kills_do_not_leave_the_site_failed() {
    for template in [LAB, PRODUCT] {
        let unit = section(template, "Unit");
        assert!(unit.contains(&"StartLimitIntervalSec=0"), "{unit:?}");
        let service = section(template, "Service");
        assert!(
            !service.iter().any(|l| l.starts_with("Restart=")),
            "starts stay request-driven"
        );
        for limit in ["MemoryMax=512M", "TasksMax=32", "CPUQuota=100%"] {
            assert!(service.contains(&limit), "{limit}");
        }
    }
}

/// D-050 (W406): the product site unit bounds disk I/O with `io.max` on the
/// sites device. `IOWeight` needs an I/O-weighting scheduler, so it is gone.
#[test]
fn product_php_bounds_its_disk_io_on_the_sites_device() {
    let service = section(PRODUCT, "Service");
    for limit in [
        "IOReadBandwidthMax=/srv/sites 64M",
        "IOWriteBandwidthMax=/srv/sites 32M",
        "IOReadIOPSMax=/srv/sites 2000",
        "IOWriteIOPSMax=/srv/sites 1000",
    ] {
        assert!(service.contains(&limit), "{limit}");
    }
    assert!(!service.iter().any(|line| line.starts_with("IOWeight=")));
}

#[test]
fn product_php_accepts_unix_sockets_and_denies_ip_egress() {
    let service = section(PRODUCT, "Service");
    let settings = |key: &str| {
        service
            .iter()
            .filter_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .collect::<Vec<_>>()
    };
    assert_eq!(settings("PrivateNetwork"), ["yes"]);
    assert_eq!(settings("RestrictAddressFamilies"), ["AF_UNIX"]);
    assert_eq!(settings("IPAddressDeny"), ["any"]);
    assert!(settings("IPAddressAllow").is_empty());
    assert_eq!(settings("StandardInput"), ["socket"]);
}

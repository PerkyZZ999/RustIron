//! W212 (B13): one LSAPI connection per OLS worker process, and a site's PHP
//! worker count must cover every OLS process, or activation is refused.
use rustiron_executor::ols::{
    LSAPI_MAX_CONNS, dropin_overrides_php, ols_workers, online_cpus, php_capacity, unit_children,
    vhost,
};

const UNIT: &str = "[Service]\nUser=%i\nEnvironment=PHP_LSAPI_CHILDREN=4 PHP_LSAPI_MAX_REQUESTS=500 TMPDIR=/srv/sites/%i/tmp\nCPUQuota=100%\n";
const PARENT: &str =
    "serverName\nuser nobody\ndisableWebAdmin 1\ninclude /etc/rustiron-ols/current/*.conf\n";

#[test]
fn vhost_renders_one_connection_per_ols_process() {
    assert_eq!(LSAPI_MAX_CONNS, 1);
    for lscache in [false, true] {
        let text = vhost("rs_blog1", "blog1.example.test", lscache);
        assert!(text.contains("\n maxConns 1\n"), "{text}");
        assert!(!text.contains("maxConns 4"));
        // OLS never starts this PHP (autoStart 0); the unit owns the count.
        assert!(!text.contains("PHP_LSAPI_CHILDREN"), "{text}");
        assert!(text.contains("\n autoStart 0\n"));
    }
}

#[test]
fn ols_worker_count_follows_the_parent_or_the_cpu_default() {
    assert_eq!(ols_workers(PARENT.as_bytes(), Some(4)), Some(4));
    assert_eq!(
        ols_workers(PARENT.as_bytes(), Some(12)),
        Some(8),
        "OLS caps the default at 8"
    );
    assert_eq!(ols_workers(PARENT.as_bytes(), None), None);
    let set = format!("httpdWorkers 2\n{PARENT}");
    assert_eq!(ols_workers(set.as_bytes(), Some(4)), Some(2));
    let spaced = format!("  httpdWorkers      6  \n{PARENT}");
    assert_eq!(ols_workers(spaced.as_bytes(), None), Some(6));
    let high = format!("httpdWorkers 40\n{PARENT}");
    assert_eq!(
        ols_workers(high.as_bytes(), Some(4)),
        Some(16),
        "OLS clamps to 1..16"
    );
    let bad = format!("httpdWorkers lots\n{PARENT}");
    assert_eq!(ols_workers(bad.as_bytes(), Some(4)), None);
    let twice = format!("httpdWorkers 2\nhttpdWorkers 3\n{PARENT}");
    assert_eq!(ols_workers(twice.as_bytes(), Some(4)), None);
}

#[test]
fn unit_children_is_the_single_environment_value() {
    assert_eq!(unit_children(UNIT), Some(4));
    assert_eq!(
        unit_children(&UNIT.replace("CHILDREN=4", "CHILDREN=16")),
        Some(16)
    );
    assert_eq!(
        unit_children("[Service]\nUser=%i\n"),
        None,
        "missing is refused"
    );
    let twice = format!("{UNIT}Environment=PHP_LSAPI_CHILDREN=8\n");
    assert_eq!(unit_children(&twice), None);
    assert_eq!(
        unit_children(&UNIT.replace("CHILDREN=4", "CHILDREN=x")),
        None
    );
    assert_eq!(
        unit_children(&UNIT.replace("CHILDREN=4", "CHILDREN=0")),
        None
    );
    let commented = UNIT.replace("Environment=", "# Environment=");
    assert_eq!(unit_children(&commented), None);
}

#[test]
fn capacity_needs_children_for_every_ols_connection() {
    let parent = PARENT.as_bytes();
    assert!(php_capacity(Some(parent), Some(4), Some(UNIT), false));
    assert!(
        !php_capacity(Some(parent), Some(8), Some(UNIT), false),
        "8 workers, 4 children"
    );
    let two = format!("httpdWorkers 2\n{PARENT}");
    assert!(php_capacity(
        Some(two.as_bytes()),
        Some(8),
        Some(UNIT),
        false
    ));
    let five = format!("httpdWorkers 5\n{PARENT}");
    assert!(!php_capacity(
        Some(five.as_bytes()),
        Some(4),
        Some(UNIT),
        false
    ));
    // Anything unknown fails closed.
    assert!(!php_capacity(None, Some(4), Some(UNIT), false));
    assert!(!php_capacity(Some(parent), None, Some(UNIT), false));
    assert!(!php_capacity(Some(parent), Some(4), None, false));
    assert!(
        !php_capacity(Some(parent), Some(4), Some(UNIT), true),
        "a drop-in override"
    );
}

#[test]
fn only_a_drop_in_touching_the_php_environment_is_an_override() {
    // The provision's own drop-in (W212 live finding) is not an override.
    let selinux = "[Service]\nSELinuxContext=system_u:system_r:rustiron_php_t:s0:c211\nEnvironment=RUSTIRON_SITE_LEVEL=s0:c211\n";
    assert!(!dropin_overrides_php(selinux));
    assert!(!dropin_overrides_php("[Service]\nCPUQuota=200%\n"));
    for hostile in [
        "[Service]\nEnvironment=PHP_LSAPI_CHILDREN=16\n",
        "[Service]\nEnvironment=\"PHP_LSAPI_CHILDREN=1\"\n",
        "[Service]\nEnvironmentFile=/etc/php.env\n",
        "[Service]\nUnsetEnvironment=PHP_LSAPI_CHILDREN\n",
        "[Service]\nExecStart=\nExecStart=/usr/bin/lsphp\n",
        "[Service]\nPassEnvironment=PHP_LSAPI_CHILDREN\n",
    ] {
        assert!(dropin_overrides_php(hostile), "{hostile}");
    }
}

#[test]
fn online_cpus_comes_from_the_affinity_syscall() {
    let cpus = online_cpus().expect("affinity readable unprivileged");
    let parallel = std::thread::available_parallelism().map_or(0, |n| n.get() as u32);
    assert!(cpus >= 1 && cpus >= parallel, "{cpus} vs {parallel}");
}

#[test]
fn online_cpus_is_the_affinity_set_not_a_sysfs_read() {
    // sched_setaffinity(None) pins only this test thread.
    let all = online_cpus().expect("affinity");
    let mut one = rustix::thread::CpuSet::new();
    let first = (0..1024)
        .find(|&cpu| rustix::thread::sched_getaffinity(None).unwrap().is_set(cpu))
        .unwrap();
    one.set(first);
    rustix::thread::sched_setaffinity(None, &one).unwrap();
    let pinned = online_cpus();
    assert_eq!(pinned, Some(1), "all={all}");
}

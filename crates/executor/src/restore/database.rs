//! D-034 (W383): the bound on the probe database during the import.
//!
//! W378 q7a: a short dump statement grew the probe database to 3 GiB in
//! about 60 s, and only the 100-second unit runtime stopped it. MariaDB has
//! no size quota for a database or a user, and every data file belongs to
//! the `mysql` account, so a file system quota cannot single out the probe.
//!
//! The helper therefore watches the import. While the import unit runs, it
//! reads the probe database's size from the server as the database root
//! twice a second. Over the cap, it locks the throwaway database user and
//! kills its connections, and the import fails. A size it cannot read for
//! [`MAX_MISSED_READS`] reads in a row also stops the import. A last read
//! after the unit ends applies the same cap.

use std::time::Duration;

/// The smallest cap: an empty WordPress database takes a few MiB.
pub(crate) const CAP_FLOOR_BYTES: u64 = 64 << 20;
/// The largest cap. The fetch ceiling bounds the dump to 2 GiB.
pub(crate) const CAP_CEILING_BYTES: u64 = 8 << 30;
/// Cap bytes per dump byte. InnoDB rows and indexes of a `mariadb-dump`
/// import take about one to three times the dump size.
const CAP_PER_DUMP_BYTE: u64 = 4;
/// Time between two size reads.
pub(crate) const POLL: Duration = Duration::from_millis(500);
/// Size reads in a row that may fail before the import is stopped.
pub(crate) const MAX_MISSED_READS: u32 = 10;
/// Server-side bound on one size read, in seconds.
const READ_SECONDS: u32 = 2;

/// The size cap for a dump of `dump_bytes`.
pub(crate) fn cap(dump_bytes: u64) -> u64 {
    dump_bytes
        .saturating_mul(CAP_PER_DUMP_BYTE)
        .saturating_add(CAP_FLOOR_BYTES)
        .min(CAP_CEILING_BYTES)
}

/// Fixed SQL for the database root: the allocated bytes of the probe's
/// InnoDB tablespaces plus the data and index bytes of its other tables.
/// `probe` is the journaled `rp_<6 hex>` name, never request text.
pub(crate) fn size_sql(probe: &str) -> String {
    format!(
        "SET STATEMENT max_statement_time={READ_SECONDS} FOR SELECT (SELECT COALESCE(SUM(ALLOCATED_SIZE),0) FROM information_schema.INNODB_SYS_TABLESPACES WHERE SUBSTRING_INDEX(NAME,'/',1)='{probe}') + (SELECT COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0) FROM information_schema.TABLES WHERE TABLE_SCHEMA='{probe}' AND ENGINE IS NOT NULL AND ENGINE<>'InnoDB');\n"
    )
}

/// Fixed SQL that stops the probe's import: no new login, then every
/// connection of the throwaway user ends.
pub(crate) fn stop_sql(probe: &str) -> String {
    format!(
        "ALTER USER '{probe}'@'localhost' ACCOUNT LOCK; KILL HARD CONNECTION USER '{probe}'@'localhost';\n"
    )
}

/// One canonical decimal byte count on one line.
pub(crate) fn parse_size(text: &str) -> Option<u64> {
    let line = text.strip_suffix('\n')?;
    let canonical = !line.is_empty()
        && line.bytes().all(|byte| byte.is_ascii_digit())
        && (line == "0" || !line.starts_with('0'));
    canonical.then(|| line.parse().ok()).flatten()
}

/// Why the watch stopped an import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stop {
    /// A read showed more than the cap.
    OverCap,
    /// [`MAX_MISSED_READS`] reads in a row failed.
    Unobserved,
}

impl Stop {
    fn as_str(self) -> &'static str {
        match self {
            Self::OverCap => "over_cap",
            Self::Unobserved => "size_unobserved",
        }
    }
}

/// What the watch saw during one import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Watch {
    pub(crate) cap: u64,
    pub(crate) peak: Option<u64>,
    pub(crate) stopped: Option<Stop>,
}

impl Watch {
    /// The receipt's `observed` member of the consistency field.
    pub(crate) fn observed(&self) -> serde_json::Value {
        serde_json::json!({
            "database_cap_bytes": self.cap,
            "database_peak_bytes": self.peak,
            "stopped": self.stopped.map(Stop::as_str),
        })
    }
}

/// Runs `run` (the import unit) on its own thread and reads the size with
/// `observe` every `poll` until it ends. Over `cap`, or after
/// [`MAX_MISSED_READS`] failed reads in a row, it calls `stop` once. A
/// stopped import never passes, whatever its unit reports.
pub(crate) fn watch<E: Send>(
    cap: u64,
    poll: Duration,
    run: impl FnOnce() -> Result<(), E> + Send,
    mut observe: impl FnMut() -> Option<u64>,
    mut stop: impl FnMut(),
) -> (bool, Watch) {
    let mut seen = Watch {
        cap,
        peak: None,
        stopped: None,
    };
    let mut missed = 0_u32;
    let mut check = |seen: &mut Watch, missed: &mut u32| -> Option<Stop> {
        match observe() {
            Some(bytes) => {
                *missed = 0;
                seen.peak = Some(seen.peak.map_or(bytes, |peak| peak.max(bytes)));
                (bytes > cap).then_some(Stop::OverCap)
            }
            None => {
                *missed += 1;
                (*missed >= MAX_MISSED_READS).then_some(Stop::Unobserved)
            }
        }
    };
    let ran = std::thread::scope(|scope| {
        let import = scope.spawn(run);
        while !import.is_finished() {
            std::thread::sleep(poll);
            if seen.stopped.is_none()
                && let Some(reason) = check(&mut seen, &mut missed)
            {
                seen.stopped = Some(reason);
                stop();
            }
        }
        import.join().is_ok_and(|result| result.is_ok())
    });
    // The last read after the unit ended: the same cap applies.
    if seen.stopped.is_none() {
        missed = MAX_MISSED_READS - 1;
        seen.stopped = check(&mut seen, &mut missed);
    }
    (ran && seen.stopped.is_none(), seen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    const FAST: Duration = Duration::from_millis(1);

    #[test]
    fn the_cap_follows_the_dump_within_fixed_bounds() {
        assert_eq!(cap(0), CAP_FLOOR_BYTES);
        assert_eq!(cap(1 << 20), CAP_FLOOR_BYTES + (4 << 20));
        assert_eq!(cap(2 << 30), CAP_CEILING_BYTES);
        assert_eq!(cap(u64::MAX), CAP_CEILING_BYTES);
        // W378 q7a: a dump of a few MiB never reaches a 3 GiB database.
        assert!(cap(8 << 20) < 3_000 << 20);
    }

    #[test]
    fn the_size_and_stop_statements_are_fixed_for_the_probe() {
        let size = size_sql("rp_0a9fbc");
        assert!(size.starts_with("SET STATEMENT max_statement_time=2 FOR SELECT"));
        assert!(size.contains("SUBSTRING_INDEX(NAME,'/',1)='rp_0a9fbc'"));
        assert!(
            size.contains("TABLE_SCHEMA='rp_0a9fbc' AND ENGINE IS NOT NULL AND ENGINE<>'InnoDB'")
        );
        assert_eq!(
            stop_sql("rp_0a9fbc"),
            "ALTER USER 'rp_0a9fbc'@'localhost' ACCOUNT LOCK; KILL HARD CONNECTION USER 'rp_0a9fbc'@'localhost';\n"
        );
    }

    #[test]
    fn only_one_canonical_count_is_a_size() {
        assert_eq!(parse_size("0\n"), Some(0));
        assert_eq!(parse_size("3221225472\n"), Some(3_221_225_472));
        for bad in [
            "",
            "12",
            "12\n\n",
            "012\n",
            "-1\n",
            "NULL\n",
            "1 2\n",
            "99999999999999999999999\n",
        ] {
            assert_eq!(parse_size(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_database_over_the_cap_stops_the_import() {
        // W378 q7a: the import grows the database until it is stopped.
        let stopped = AtomicBool::new(false);
        let mut size = 0;
        let (passed, seen) = watch(
            100,
            FAST,
            || {
                while !stopped.load(Ordering::SeqCst) {
                    std::thread::sleep(FAST);
                }
                Err::<(), ()>(())
            },
            || {
                size += 40;
                Some(size)
            },
            || stopped.store(true, Ordering::SeqCst),
        );
        assert!(!passed);
        assert_eq!(seen.stopped, Some(Stop::OverCap));
        assert!(seen.peak.is_some_and(|peak| peak > 100 && peak <= 120));
        assert_eq!(seen.observed()["stopped"], "over_cap");
    }

    #[test]
    fn a_stopped_import_fails_even_when_its_unit_succeeds() {
        let (passed, seen) = watch(
            10,
            FAST,
            || {
                std::thread::sleep(Duration::from_millis(50));
                Ok::<(), ()>(())
            },
            || Some(11),
            || {},
        );
        assert!(!passed);
        assert_eq!(seen.stopped, Some(Stop::OverCap));
    }

    #[test]
    fn an_unreadable_size_stops_the_import() {
        let stops = std::cell::Cell::new(0);
        let (passed, seen) = watch(
            u64::MAX,
            FAST,
            || {
                std::thread::sleep(Duration::from_millis(100));
                Ok::<(), ()>(())
            },
            || None,
            || stops.set(stops.get() + 1),
        );
        assert!(!passed);
        assert_eq!(seen.stopped, Some(Stop::Unobserved));
        assert_eq!(stops.get(), 1, "stop runs once");
    }

    #[test]
    fn a_bounded_import_passes_and_the_last_read_applies_the_cap() {
        let (passed, seen) = watch(100, FAST, || Ok::<(), ()>(()), || Some(60), || {});
        assert!(passed);
        assert_eq!(seen.peak, Some(60));
        assert_eq!(seen.stopped, None);
        // A fast import that ends over the cap fails at the last read.
        let (passed, seen) = watch(100, FAST, || Ok::<(), ()>(()), || Some(101), || {});
        assert!(!passed);
        assert_eq!(seen.stopped, Some(Stop::OverCap));
        // A failed import fails.
        assert!(!watch(100, FAST, || Err::<(), ()>(()), || Some(1), || {}).0);
    }
}

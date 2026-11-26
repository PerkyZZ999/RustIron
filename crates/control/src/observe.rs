use rustiron_contracts::{
    DoctorReport, Observation, ObservationSource, Text, Timestamp, UnknownReason,
};
use std::{
    fs::File,
    io::{self, Read},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_RELEASE_BYTES: usize = 16 * 1024;

pub(crate) fn doctor() -> DoctorReport {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| Timestamp::try_from(d.as_secs()).ok());
    let release = read_release();
    let kernel = rustix::system::uname();
    let os_field = |key| match &release {
        Ok(content) => release_field(content, key).map_or_else(
            || unknown(UnknownReason::Unavailable),
            |value| observed(value, time, ObservationSource::OsRelease),
        ),
        Err(reason) => unknown(*reason),
    };
    DoctorReport {
        os_name: os_field("NAME"),
        os_version: os_field("VERSION_ID"),
        kernel_release: kernel.release().to_str().ok().map_or_else(
            || unknown(UnknownReason::Unavailable),
            |value| observed(value.to_owned(), time, ObservationSource::Kernel),
        ),
        architecture: kernel.machine().to_str().ok().map_or_else(
            || unknown(UnknownReason::Unavailable),
            |value| observed(value.to_owned(), time, ObservationSource::Kernel),
        ),
        hosting_profile: unknown(UnknownReason::NotChecked),
        site_confinement: unknown(UnknownReason::NotChecked),
    }
}

fn unknown(reason: UnknownReason) -> Observation<Text> {
    Observation::Unknown { reason }
}

fn observed(
    value: String,
    time: Option<Timestamp>,
    source: ObservationSource,
) -> Observation<Text> {
    match (Text::try_from(value), time) {
        (Ok(value), Some(observed_at)) => Observation::Observed {
            value,
            observed_at,
            source,
        },
        _ => unknown(UnknownReason::Unavailable),
    }
}

fn read_release() -> Result<String, UnknownReason> {
    let map_error = |error: io::Error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            UnknownReason::PermissionDenied
        } else {
            UnknownReason::Unavailable
        }
    };
    // Fixed administrator-controlled metadata; no caller-selected path or shell evaluation.
    let file = File::open("/etc/os-release").map_err(map_error)?;
    if !file.metadata().map_err(map_error)?.is_file() {
        return Err(UnknownReason::Unavailable);
    }
    let mut bytes = Vec::new();
    file.take((MAX_RELEASE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(map_error)?;
    if bytes.len() > MAX_RELEASE_BYTES {
        return Err(UnknownReason::Unavailable);
    }
    String::from_utf8(bytes).map_err(|_| UnknownReason::Unavailable)
}

// Conservative os-release subset: malformed/ambiguous data becomes unknown, never executable.
fn release_field(content: &str, key: &str) -> Option<String> {
    let mut matches = content.lines().filter_map(|line| {
        line.split_once('=')
            .filter(|(name, _)| *name == key)
            .map(|(_, value)| value)
    });
    let value = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    let value = if let Some(quoted) = value.strip_prefix('"') {
        let body = quoted.strip_suffix('"')?;
        let mut result = String::new();
        let mut characters = body.chars();
        while let Some(character) = characters.next() {
            match character {
                '\\' => match characters.next()? {
                    escaped @ ('\\' | '"' | '$' | '`') => result.push(escaped),
                    _ => return None,
                },
                '"' => return None,
                other => result.push(other),
            }
        }
        result
    } else if let Some(quoted) = value.strip_prefix('\'') {
        let body = quoted.strip_suffix('\'')?;
        if body.contains('\'') {
            return None;
        }
        body.to_owned()
    } else {
        if value
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '\\'))
        {
            return None;
        }
        value.to_owned()
    };
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_values_are_data_and_ambiguous_values_are_unknown() {
        assert_eq!(
            release_field("NAME=\"AlmaLinux\"\nVERSION_ID='10'", "NAME"),
            Some("AlmaLinux".into())
        );
        assert_eq!(
            release_field("NAME='$(not-executed)'", "NAME"),
            Some("$(not-executed)".into())
        );
        for content in [
            "NAME=a\nNAME=b",
            "NAME=\"unfinished",
            "NAME=a b",
            "NAME=",
            "NAME=\"bad\\q\"",
        ] {
            assert_eq!(release_field(content, "NAME"), None);
        }
        assert_eq!(
            observed(
                "x".repeat(513),
                Timestamp::try_from(1).ok(),
                ObservationSource::OsRelease
            ),
            unknown(UnknownReason::Unavailable)
        );
        assert_eq!(
            observed("host".into(), None, ObservationSource::Kernel),
            unknown(UnknownReason::Unavailable)
        );
    }
}

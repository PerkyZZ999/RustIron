use crate::{Id, Observation, ProtocolError, ReadData, Response, SiteSummary, Text};

/// Escapes terminal controls, newlines and bidirectional formatting in untrusted text.
///
/// Unicode letters remain readable. This is terminal-context escaping, not
/// HTML escaping or a substitute for producer-side credential redaction.
pub fn escape_human(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control()
            || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// Formats a read outcome with explicit observation state and escaped display data.
///
/// Producers must supply approved/redacted metadata. Escaping does not detect
/// credentials or remove them from otherwise valid text.
pub fn render_human(response: &Response) -> Result<String, ProtocolError> {
    crate::codec::validate_response(response)?;
    Ok(match &response.result {
        Err(error) => format!(
            "Error {:?}: {}\n",
            error.code(),
            escape_human(error.message())
        ),
        Ok(ReadData::Doctor(report)) => [
            "Host inspection (read-only)".to_owned(),
            format!("OS name: {}", observation(&report.os_name, Text::as_str)),
            format!(
                "OS version: {}",
                observation(&report.os_version, Text::as_str)
            ),
            format!(
                "Kernel: {}",
                observation(&report.kernel_release, Text::as_str)
            ),
            format!(
                "Architecture: {}",
                observation(&report.architecture, Text::as_str)
            ),
            format!(
                "Hosting profile: {}",
                observation(&report.hosting_profile, Text::as_str)
            ),
            format!(
                "Site confinement: {}",
                observation(&report.site_confinement, Text::as_str)
            ),
            String::new(),
        ]
        .join("\n"),
        Ok(ReadData::SiteList(page)) => {
            let mut lines = vec![format!("Sites: {} record(s)", page.items.len())];
            for site in &page.items {
                lines.push(site_line(site));
            }
            lines.push(match &page.next_cursor {
                Some(cursor) => format!("Next cursor: {}", cursor.as_str()),
                None => "End of list".to_owned(),
            });
            lines.push(String::new());
            lines.join("\n")
        }
        Ok(ReadData::SiteInspect(site)) => format!(
            "{}\nConfiguration generation: {}\n",
            site_line(&site.site),
            observation(&site.configuration_generation, Id::as_str)
        ),
        Ok(ReadData::OperationStatus(status)) => format!(
            "Operation: {}\nRecorded state: {:?}\n",
            status.operation_id.as_str(),
            status.state
        ),
        Ok(ReadData::EvidenceExport(evidence)) => format!(
            "Operation: {}\nSelf-attested receipt. Not independent proof.\n{}\n{}\n",
            evidence.operation_id.as_str(),
            receipt_signature_line(&evidence.receipt),
            // W420 (T13): JSON keeps DEL, C1 controls, and bidirectional
            // formatting raw, and a receipt carries restored-site text.
            escape_human(
                &serde_json::to_string(&evidence.receipt).unwrap_or_else(|_| "{}".to_owned())
            )
        ),
    })
}

/// W392: the signature state of a receipt. The CLI does not verify it.
fn receipt_signature_line(receipt: &crate::execution::EvidenceReceipt) -> String {
    match &receipt.signature {
        Some(signature) => format!(
            "Signature: self-attested, signed by host receipt key {}. Not verified here; run check_receipt.py with the recorded public key.",
            signature.key_fingerprint
        ),
        None => "Signature: none (self-attested, unsigned).".to_owned(),
    }
}

fn site_line(site: &SiteSummary) -> String {
    let provenance = match &site.inventory {
        Some(report) => format!("operator_report; unix_seconds={}", report.reported_at.get()),
        None => "provenance unknown".to_owned(),
    };
    format!(
        "{} | {} | {:?} [{provenance}]",
        site.site_id.as_str(),
        escape_human(site.name.as_str()),
        site.ownership
    )
}

fn observation<T>(value: &Observation<T>, text: impl Fn(&T) -> &str) -> String {
    let (label, value, observed_at, source) = match value {
        Observation::Unknown { reason } => return format!("unknown ({reason:?})"),
        Observation::Observed {
            value,
            observed_at,
            source,
        } => ("observed", value, observed_at, source),
        Observation::Inferred {
            value,
            observed_at,
            source,
        } => ("inferred", value, observed_at, source),
        Observation::Stale {
            value,
            observed_at,
            source,
        } => ("stale", value, observed_at, source),
    };
    format!(
        "{} [{label}; source={source:?}; unix_seconds={}]",
        escape_human(text(value)),
        observed_at.get()
    )
}

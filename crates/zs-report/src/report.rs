//! Report collection (from SQLite) and rendering (JSON / CSV / HTML).

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use zs_core::error::ZsResult;
use zs_core::model::{FindingRow, QuarantineEntry, ScanRow, Severity, StoredEvent};
use zs_core::storage::Storage;
use zs_core::util::{format_ts, human_bytes, human_duration, now_secs};

/// Options for building a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportOptions {
    /// Only include records from the last N days (0 = no time limit).
    pub days: u32,
    /// Maximum rows per section.
    pub limit: u32,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            days: 7,
            limit: 1000,
        }
    }
}

impl ReportOptions {
    /// Clamp to sane bounds (days ≤ 10 years, 1 ≤ limit ≤ 10 000).
    pub fn clamped(self) -> Self {
        Self {
            days: self.days.min(3650),
            limit: self.limit.clamp(1, 10_000),
        }
    }

    /// Lower bound timestamp: 0 means "no lower bound".
    pub fn since(&self) -> i64 {
        if self.days == 0 {
            0
        } else {
            now_secs() - i64::from(self.days) * 86_400
        }
    }
}

/// Global counters plus period totals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub scans_total: u64,
    pub threats_total: u64,
    pub findings_total: u64,
    pub quarantine_entries: u64,
    pub signatures: u64,
    pub clean_cache_entries: u64,
    /// Findings inside the reporting window (capped by `limit`).
    pub findings_in_period: u64,
    /// Scans inside the reporting window (capped by `limit`).
    pub scans_in_period: u64,
}

/// Everything a report renders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportData {
    pub generated_at: i64,
    pub version: String,
    pub host: String,
    pub period_days: u32,
    pub limit: u32,
    pub summary: ReportSummary,
    pub scans: Vec<ScanRow>,
    pub findings: Vec<FindingRow>,
    pub quarantine: Vec<QuarantineEntry>,
    /// Alert-worthy events in the window (severity ≥ medium).
    pub events: Vec<StoredEvent>,
}

/// Best-effort hostname (Linux: `/proc/sys/kernel/hostname`).
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

/// Collect a report from storage.
pub fn collect(storage: &Storage, version: &str, opts: ReportOptions) -> ZsResult<ReportData> {
    let opts = opts.clamped();
    let since = opts.since();

    let scans = storage.list_scans(opts.limit, since)?;
    let findings = storage.list_findings_rows(opts.limit, since)?;
    let events = storage
        .list_events_since(opts.limit, since)?
        .into_iter()
        .filter(|event| event.severity >= Severity::Medium)
        .collect::<Vec<_>>();
    let mut quarantine = storage.list_quarantine()?;
    let quarantine_entries = quarantine.len() as u64;
    quarantine.truncate(opts.limit as usize);

    let summary = ReportSummary {
        scans_total: storage.scan_count()?,
        threats_total: storage.threat_count()?,
        findings_total: storage.finding_count()?,
        quarantine_entries,
        signatures: storage.signature_count()?,
        clean_cache_entries: storage.clean_cache_len().unwrap_or(0),
        findings_in_period: findings.len() as u64,
        scans_in_period: scans.len() as u64,
    };

    Ok(ReportData {
        generated_at: now_secs(),
        version: version.to_string(),
        host: hostname(),
        period_days: opts.days,
        limit: opts.limit,
        summary,
        scans,
        findings,
        quarantine,
        events,
    })
}

// ------------------------------------------------------------------ rendering

/// Pretty JSON of the whole report.
pub fn render_json(data: &ReportData) -> ZsResult<String> {
    Ok(serde_json::to_string_pretty(data)?)
}

/// Table to export as CSV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsvSection {
    Findings,
    Scans,
    Events,
    Quarantine,
}

impl CsvSection {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "findings" => Some(CsvSection::Findings),
            "scans" => Some(CsvSection::Scans),
            "events" => Some(CsvSection::Events),
            "quarantine" => Some(CsvSection::Quarantine),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CsvSection::Findings => "findings",
            CsvSection::Scans => "scans",
            CsvSection::Events => "events",
            CsvSection::Quarantine => "quarantine",
        }
    }
}

/// RFC 4180 style field escaping.
fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_row(fields: &[String]) -> String {
    let mut line = fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    line.push('\n');
    line
}

fn detections_brief(detections: &[zs_core::model::Detection]) -> String {
    detections
        .iter()
        .map(|d| format!("{}: {} (+{})", d.name, d.description, d.score))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Render one section as CSV.
pub fn render_csv(data: &ReportData, section: CsvSection) -> String {
    let mut out = String::new();
    match section {
        CsvSection::Findings => {
            out.push_str(
                "id,ts,scan_id,path,size,score,severity,verdict,quarantined,sha256,detections\n",
            );
            for row in &data.findings {
                let f = &row.finding;
                out.push_str(&csv_row(&[
                    row.id.to_string(),
                    row.ts.to_string(),
                    row.scan_id.clone().unwrap_or_default(),
                    f.path.clone(),
                    f.size.to_string(),
                    f.score.to_string(),
                    f.severity.as_str().to_string(),
                    f.verdict.as_str().to_string(),
                    f.quarantined.to_string(),
                    f.hashes.sha256.clone(),
                    detections_brief(&f.detections),
                ]));
            }
        }
        CsvSection::Scans => {
            out.push_str("id,ts,target,files,bytes,findings,max_score,duration_ms\n");
            for scan in &data.scans {
                out.push_str(&csv_row(&[
                    scan.id.clone(),
                    scan.ts.to_string(),
                    scan.target.clone(),
                    scan.files.to_string(),
                    scan.bytes.to_string(),
                    scan.findings.to_string(),
                    scan.max_score.to_string(),
                    scan.duration_ms.to_string(),
                ]));
            }
        }
        CsvSection::Events => {
            out.push_str("id,ts,kind,severity,payload\n");
            for event in &data.events {
                out.push_str(&csv_row(&[
                    event.id.to_string(),
                    event.ts.to_string(),
                    event.kind.clone(),
                    event.severity.as_str().to_string(),
                    serde_json::to_string(&event.payload).unwrap_or_default(),
                ]));
            }
        }
        CsvSection::Quarantine => {
            out.push_str("id,ts,original_path,file_name,sha256,size,restored,detections\n");
            for entry in &data.quarantine {
                out.push_str(&csv_row(&[
                    entry.id.to_string(),
                    entry.ts.to_string(),
                    entry.original_path.clone(),
                    entry.file_name.clone(),
                    entry.sha256.clone(),
                    entry.size.to_string(),
                    entry.restored.to_string(),
                    detections_brief(&entry.detections),
                ]));
            }
        }
    }
    out
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

const HTML_CSS: &str = "\
:root { color-scheme: light; }\n\
body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; color: #1f2328; }\n\
h1 { font-size: 1.5rem; margin-bottom: .25rem; }\n\
.meta { color: #57606a; font-size: .9rem; margin-top: 0; }\n\
.cards { display: flex; flex-wrap: wrap; gap: .75rem; margin: 1rem 0 1.5rem; }\n\
.card { border: 1px solid #d0d7de; border-radius: 8px; padding: .6rem .9rem; min-width: 8rem; }\n\
.card .value { font-size: 1.4rem; font-weight: 600; }\n\
.card .label { color: #57606a; font-size: .8rem; text-transform: uppercase; letter-spacing: .03em; }\n\
h2 { font-size: 1.1rem; border-bottom: 1px solid #d0d7de; padding-bottom: .3rem; margin-top: 2rem; }\n\
table { border-collapse: collapse; width: 100%; font-size: .85rem; }\n\
th, td { border: 1px solid #d0d7de; padding: .35rem .5rem; text-align: left; vertical-align: top; }\n\
th { background: #f6f8fa; }\n\
tr:nth-child(even) td { background: #fafbfc; }\n\
.sev { font-weight: 600; padding: 0 .35rem; border-radius: 4px; font-size: .8rem; color: #fff; }\n\
.sev-critical { background: #8b1a1a; }\n\
.sev-high { background: #d1242f; }\n\
.sev-medium { background: #bf8700; }\n\
.sev-low { background: #0969da; }\n\
.sev-info { background: #6e7781; }\n\
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }\n\
.small { font-size: .78rem; }\n\
.empty { color: #57606a; font-style: italic; }\n\
footer { margin-top: 2rem; color: #57606a; font-size: .8rem; }\n";

fn sev_badge(severity: Severity) -> String {
    format!(
        "<span class=\"sev sev-{}\">{}</span>",
        severity.as_str(),
        severity.label()
    )
}

fn table_or_empty(headers: &[&str], rows: &[String]) -> String {
    if rows.is_empty() {
        return "<p class=\"empty\">No records in this period.</p>".to_string();
    }
    let mut out = String::from("<table><thead><tr>");
    for header in headers {
        let _ = write!(out, "<th>{}</th>", escape_html(header));
    }
    out.push_str("</tr></thead><tbody>");
    out.push_str(&rows.concat());
    out.push_str("</tbody></table>");
    out
}

/// Render a complete, self-contained HTML page (no external assets, no JS).
pub fn render_html(data: &ReportData) -> String {
    let period = if data.period_days == 0 {
        "all time".to_string()
    } else {
        format!("last {} day(s)", data.period_days)
    };
    let mut page = String::new();
    let _ = write!(
        page,
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>ZeroShield report — {}</title>\n<style>\n{}</style>\n</head>\n<body>\n",
        escape_html(&data.host),
        HTML_CSS
    );
    let _ = write!(
        page,
        "<h1>ZeroShield report</h1>\n\
         <p class=\"meta\">host <strong>{}</strong> · zeroshield {} · generated {} · period: {} · limit {} rows/section</p>\n",
        escape_html(&data.host),
        escape_html(&data.version),
        escape_html(&format_ts(data.generated_at)),
        escape_html(&period),
        data.limit
    );

    // Summary cards.
    page.push_str("<div class=\"cards\">\n");
    let cards: [(&str, String); 6] = [
        ("scans", data.summary.scans_total.to_string()),
        ("threats", data.summary.threats_total.to_string()),
        (
            "findings (period)",
            data.summary.findings_in_period.to_string(),
        ),
        ("quarantine", data.summary.quarantine_entries.to_string()),
        ("signatures", data.summary.signatures.to_string()),
        ("clean cache", data.summary.clean_cache_entries.to_string()),
    ];
    for (label, value) in cards {
        let _ = writeln!(
            page,
            "<div class=\"card\"><div class=\"value\">{}</div><div class=\"label\">{}</div></div>",
            escape_html(&value),
            escape_html(label)
        );
    }
    page.push_str("</div>\n");

    // Scans.
    page.push_str("<h2>Scans</h2>\n");
    let rows: Vec<String> = data
        .scans
        .iter()
        .map(|scan| {
            format!(
                "<tr><td class=\"mono small\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td>\
                 <td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                escape_html(&format_ts(scan.ts)),
                escape_html(&scan.id),
                escape_html(&scan.target),
                scan.files,
                escape_html(&human_bytes(scan.bytes)),
                scan.findings,
                scan.max_score,
                escape_html(&human_duration(scan.duration_ms)),
            )
        })
        .collect();
    page.push_str(&table_or_empty(
        &[
            "when",
            "scan id",
            "target",
            "files",
            "bytes",
            "findings",
            "max score",
            "duration",
        ],
        &rows,
    ));

    // Findings.
    page.push_str("<h2>Findings</h2>\n");
    let rows: Vec<String> = data
        .findings
        .iter()
        .map(|row| {
            let f = &row.finding;
            format!(
                "<tr><td class=\"mono small\">{}</td><td class=\"mono\">{}</td><td>{}</td>\
                 <td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"mono small\">{}</td></tr>\n",
                escape_html(&format_ts(row.ts)),
                escape_html(&f.path),
                escape_html(&f.score.to_string()),
                sev_badge(f.severity),
                escape_html(f.verdict.as_str()),
                if f.quarantined { "yes" } else { "no" },
                escape_html(&detections_brief(&f.detections)),
                escape_html(&f.hashes.sha256),
            )
        })
        .collect();
    page.push_str(&table_or_empty(
        &[
            "when",
            "path",
            "score",
            "severity",
            "verdict",
            "quarantined",
            "detections",
            "sha256",
        ],
        &rows,
    ));

    // Quarantine.
    page.push_str("<h2>Quarantine</h2>\n");
    let rows: Vec<String> = data
        .quarantine
        .iter()
        .map(|entry| {
            format!(
                "<tr><td>{}</td><td class=\"mono small\">{}</td><td class=\"mono\">{}</td>\
                 <td class=\"mono small\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                entry.id,
                escape_html(&format_ts(entry.ts)),
                escape_html(&entry.original_path),
                escape_html(&entry.sha256),
                escape_html(&human_bytes(entry.size)),
                escape_html(&detections_brief(&entry.detections)),
                if entry.restored {
                    "restored"
                } else {
                    "quarantined"
                },
            )
        })
        .collect();
    page.push_str(&table_or_empty(
        &[
            "id",
            "when",
            "original path",
            "sha256",
            "size",
            "detections",
            "status",
        ],
        &rows,
    ));

    // Alerts (persisted events with severity ≥ medium).
    page.push_str("<h2>Alerts</h2>\n");
    let rows: Vec<String> = data
        .events
        .iter()
        .map(|event| {
            let payload = serde_json::to_string(&event.payload).unwrap_or_default();
            let payload = if payload.chars().count() > 160 {
                let mut truncated: String = payload.chars().take(160).collect();
                truncated.push('…');
                truncated
            } else {
                payload
            };
            format!(
                "<tr><td class=\"mono small\">{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"mono small\">{}</td></tr>\n",
                escape_html(&format_ts(event.ts)),
                escape_html(&event.kind),
                sev_badge(event.severity),
                escape_html(&payload),
            )
        })
        .collect();
    page.push_str(&table_or_empty(
        &["when", "kind", "severity", "payload"],
        &rows,
    ));

    page.push_str(
        "<footer>Generated by ZeroShield. This file is self-contained and safe to archive or share.</footer>\n</body>\n</html>\n",
    );
    page
}

#[cfg(test)]
mod tests {
    use super::*;
    use zs_core::model::{Detection, Finding, Hashes, QuarantineEntry, Verdict};

    fn storage_with_data() -> Storage {
        let storage = Storage::open_in_memory().unwrap();
        storage
            .record_scan("scan-1", "/home/<user>", 5, 2048, 1, 100, 42)
            .unwrap();
        let finding = Finding {
            path: "/home/<user>/bad\"file\".bin,comma".into(),
            size: 68,
            hashes: Hashes {
                sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".into(),
                sha1: "3395856ce81f2b7382dee72602f798b642f14140".into(),
                md5: "44d88612fea8a8f36de82e1278abb02f".into(),
                size: 68,
            },
            score: 100,
            severity: Severity::Critical,
            verdict: Verdict::Malicious,
            detections: vec![Detection::new(
                "signature",
                "eicar",
                "EICAR <test> & file",
                100,
            )],
            quarantined: true,
        };
        storage.record_finding(Some("scan-1"), &finding).unwrap();
        storage
            .record_event(
                "scan_finding",
                Severity::Critical,
                &serde_json::json!({"path": "/x"}),
            )
            .unwrap();
        storage
            .record_event("info", Severity::Info, &serde_json::json!({}))
            .unwrap();
        storage
            .insert_quarantine(&QuarantineEntry {
                id: 0,
                ts: now_secs(),
                original_path: "/home/<user>/bad.bin".into(),
                file_name: "bad.bin".into(),
                quarantine_path: "/var/lib/zeroshield/quarantine/bad.bin".into(),
                sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".into(),
                size: 68,
                mode: 0,
                detections: finding.detections.clone(),
                restored: false,
            })
            .unwrap();
        storage
    }

    #[test]
    fn collect_gathers_all_sections() {
        let storage = storage_with_data();
        let data = collect(&storage, "0.1.0", ReportOptions::default()).unwrap();
        assert_eq!(data.version, "0.1.0");
        assert_eq!(data.period_days, 7);
        assert_eq!(data.summary.scans_total, 1);
        assert_eq!(data.summary.threats_total, 1);
        assert_eq!(data.summary.findings_total, 1);
        assert_eq!(data.summary.findings_in_period, 1);
        assert_eq!(data.summary.quarantine_entries, 1);
        assert_eq!(data.scans.len(), 1);
        assert_eq!(data.findings.len(), 1);
        assert_eq!(data.quarantine.len(), 1);
        // Info events are filtered out; critical ones stay.
        assert_eq!(data.events.len(), 1);
        assert_eq!(data.events[0].kind, "scan_finding");
    }

    #[test]
    fn options_clamp_and_since() {
        let opts = ReportOptions {
            days: 100_000,
            limit: 0,
        }
        .clamped();
        assert_eq!(opts.days, 3650);
        assert_eq!(opts.limit, 1);
        assert_eq!(ReportOptions { days: 0, limit: 10 }.since(), 0);
        let since = ReportOptions { days: 1, limit: 10 }.since();
        assert!(since > 0 && since <= now_secs());
    }

    #[test]
    fn json_roundtrips() {
        let storage = storage_with_data();
        let data = collect(&storage, "0.1.0", ReportOptions::default()).unwrap();
        let json = render_json(&data).unwrap();
        let back: ReportData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.summary.threats_total, 1);
        assert_eq!(back.findings[0].finding.path, data.findings[0].finding.path);
    }

    #[test]
    fn csv_quotes_hostile_fields() {
        let storage = storage_with_data();
        let data = collect(&storage, "0.1.0", ReportOptions::default()).unwrap();
        let csv = render_csv(&data, CsvSection::Findings);
        let header = csv.lines().next().unwrap();
        assert_eq!(
            header,
            "id,ts,scan_id,path,size,score,severity,verdict,quarantined,sha256,detections"
        );
        // The path contains quotes and a comma: it must be quoted and doubled.
        assert!(csv.contains("\"/home/<user>/bad\"\"file\"\".bin,comma\""));
        let scans = render_csv(&data, CsvSection::Scans);
        assert!(scans.lines().nth(1).unwrap().starts_with("scan-1,"));
        let events = render_csv(&data, CsvSection::Events);
        assert!(events.lines().count() == 2);
        let quarantine = render_csv(&data, CsvSection::Quarantine);
        assert!(quarantine.contains("bad.bin"));
        assert_eq!(CsvSection::parse("findings"), Some(CsvSection::Findings));
        assert_eq!(CsvSection::parse("SCANS"), Some(CsvSection::Scans));
        assert_eq!(CsvSection::parse("nope"), None);
    }

    #[test]
    fn csv_empty_sections_render_header_only() {
        let storage = Storage::open_in_memory().unwrap();
        let data = collect(&storage, "0.1.0", ReportOptions::default()).unwrap();
        for section in [
            CsvSection::Findings,
            CsvSection::Scans,
            CsvSection::Events,
            CsvSection::Quarantine,
        ] {
            let csv = render_csv(&data, section);
            assert_eq!(csv.lines().count(), 1, "section {:?}", section);
        }
    }

    #[test]
    fn html_escapes_hostile_strings() {
        let storage = storage_with_data();
        let data = collect(&storage, "0.1.0", ReportOptions::default()).unwrap();
        let html = render_html(&data);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("ZeroShield report"));
        assert!(html.contains("EICAR &lt;test&gt; &amp; file"));
        assert!(html.contains("bad&quot;file&quot;.bin,comma"));
        assert!(html.contains("/home/&lt;user&gt;/bad.bin"));
        // No raw script-capable construct from the data leaks through.
        assert!(!html.contains("<test>"));
        assert!(html.contains("sev-critical"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn html_handles_empty_data() {
        let storage = Storage::open_in_memory().unwrap();
        let data = collect(&storage, "0.1.0", ReportOptions::default()).unwrap();
        let html = render_html(&data);
        assert!(html.contains("No records in this period."));
        assert!(html.contains("all time") || html.contains("last 7 day"));
    }

    #[test]
    fn html_period_label() {
        let storage = Storage::open_in_memory().unwrap();
        let data = collect(&storage, "0.1.0", ReportOptions { days: 0, limit: 10 }).unwrap();
        assert!(render_html(&data).contains("all time"));
    }
}

//! Metrics collection and rendering (Prometheus text format / journald).

use serde::{Deserialize, Serialize};

/// Prometheus metric kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    Counter,
    Gauge,
}

impl MetricKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MetricKind::Counter => "counter",
            MetricKind::Gauge => "gauge",
        }
    }
}

/// A single metric sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub help: String,
    pub kind: MetricKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<(String, String)>,
    pub value: f64,
}

/// The rendered-ready set of metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSet {
    pub metrics: Vec<Metric>,
}

/// Raw values gathered by the daemon (or from local mode) before they are
/// turned into a [`MetricSet`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsInput {
    /// Whether the daemon is reachable. When false the storage-derived
    /// metrics are still truthful (same SQLite file) but `zeroshield_up` is 0.
    pub up: bool,
    pub version: String,
    pub uptime_secs: u64,
    pub scans_total: u64,
    pub threats_total: u64,
    pub findings_total: u64,
    pub quarantine_entries: u64,
    pub signatures_total: u64,
    pub rules_total: u64,
    pub clean_cache_entries: u64,
    pub watch_sessions: u64,
    pub watched_dirs: u64,
    pub net_rules_total: u64,
    pub procmon_processes: u64,
    /// Event count per severity label (`info`, `low`, `medium`, ...).
    pub events_by_severity: Vec<(String, u64)>,
}

fn metric(name: &str, help: &str, kind: MetricKind, value: f64) -> Metric {
    Metric {
        name: name.to_string(),
        help: help.to_string(),
        kind,
        labels: Vec::new(),
        value,
    }
}

/// Turn raw inputs into the metric catalog.
pub fn collect_metrics(input: &MetricsInput) -> MetricSet {
    let mut metrics = Vec::new();
    metrics.push(metric(
        "zeroshield_up",
        "Whether the ZeroShield daemon is reachable (1) or not (0).",
        MetricKind::Gauge,
        if input.up { 1.0 } else { 0.0 },
    ));
    metrics.push(Metric {
        name: "zeroshield_info".into(),
        help: "Build information; the value is always 1.".into(),
        kind: MetricKind::Gauge,
        labels: vec![("version".into(), input.version.clone())],
        value: 1.0,
    });
    metrics.push(metric(
        "zeroshield_uptime_seconds",
        "Seconds since the daemon started (0 when not reachable).",
        MetricKind::Gauge,
        if input.up {
            input.uptime_secs as f64
        } else {
            0.0
        },
    ));
    metrics.push(metric(
        "zeroshield_scans_total",
        "Total number of finished scans.",
        MetricKind::Counter,
        input.scans_total as f64,
    ));
    metrics.push(metric(
        "zeroshield_threats_total",
        "Total number of recorded threats (malicious or suspicious findings).",
        MetricKind::Counter,
        input.threats_total as f64,
    ));
    metrics.push(metric(
        "zeroshield_findings_total",
        "Total number of recorded findings (any verdict).",
        MetricKind::Counter,
        input.findings_total as f64,
    ));
    metrics.push(metric(
        "zeroshield_quarantine_entries",
        "Entries currently tracked in the quarantine store.",
        MetricKind::Gauge,
        input.quarantine_entries as f64,
    ));
    metrics.push(metric(
        "zeroshield_signatures_total",
        "Hash signatures known to the scanner.",
        MetricKind::Gauge,
        input.signatures_total as f64,
    ));
    metrics.push(metric(
        "zeroshield_rules_total",
        "Content rules loaded by the scanner.",
        MetricKind::Gauge,
        input.rules_total as f64,
    ));
    metrics.push(metric(
        "zeroshield_clean_cache_entries",
        "Files currently remembered by the clean-file cache.",
        MetricKind::Gauge,
        input.clean_cache_entries as f64,
    ));
    metrics.push(metric(
        "zeroshield_watch_sessions",
        "Active real-time watch sessions.",
        MetricKind::Gauge,
        input.watch_sessions as f64,
    ));
    metrics.push(metric(
        "zeroshield_watched_dirs",
        "Directories currently watched in real time.",
        MetricKind::Gauge,
        input.watched_dirs as f64,
    ));
    metrics.push(metric(
        "zeroshield_net_rules",
        "Enabled network rules (IPS blocklist).",
        MetricKind::Gauge,
        input.net_rules_total as f64,
    ));
    metrics.push(metric(
        "zeroshield_procmon_processes",
        "Processes visible to the process monitor on the last pass.",
        MetricKind::Gauge,
        input.procmon_processes as f64,
    ));
    for (severity, count) in &input.events_by_severity {
        metrics.push(Metric {
            name: "zeroshield_events_total".into(),
            help: "Persisted events by severity.".into(),
            kind: MetricKind::Counter,
            labels: vec![("severity".into(), severity.clone())],
            value: *count as f64,
        });
    }
    MetricSet { metrics }
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn fmt_value(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

/// Render the set in Prometheus text exposition format.
pub fn render_prometheus(set: &MetricSet) -> String {
    let mut out = String::new();
    let mut last: Option<(&str, MetricKind)> = None;
    for m in &set.metrics {
        // Only the first sample of a family carries HELP/TYPE.
        if last != Some((m.name.as_str(), m.kind)) {
            out.push_str(&format!("# HELP {} {}\n", m.name, m.help));
            out.push_str(&format!("# TYPE {} {}\n", m.name, m.kind.as_str()));
            last = Some((m.name.as_str(), m.kind));
        }
        out.push_str(&m.name);
        if !m.labels.is_empty() {
            out.push('{');
            let labels = m
                .labels
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, escape_label(v)))
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&labels);
            out.push('}');
        }
        out.push(' ');
        out.push_str(&fmt_value(m.value));
        out.push('\n');
    }
    out
}

/// Render the set as a single journald friendly line of `key=value` pairs.
pub fn render_journald(set: &MetricSet) -> String {
    let mut out = String::from("zeroshield metrics");
    for m in &set.metrics {
        let mut key = m.name.trim_start_matches("zeroshield_").to_string();
        for (label, value) in &m.labels {
            key.push('_');
            key.push_str(label);
            key.push('_');
            key.push_str(&value.replace(' ', "_"));
        }
        out.push(' ');
        out.push_str(&key);
        out.push('=');
        out.push_str(&fmt_value(m.value));
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> MetricsInput {
        MetricsInput {
            up: true,
            version: "0.1.0".into(),
            uptime_secs: 90,
            scans_total: 12,
            threats_total: 2,
            findings_total: 5,
            quarantine_entries: 1,
            signatures_total: 3,
            rules_total: 12,
            clean_cache_entries: 42,
            watch_sessions: 1,
            watched_dirs: 3,
            net_rules_total: 0,
            procmon_processes: 480,
            events_by_severity: vec![("info".into(), 10), ("critical".into(), 2)],
        }
    }

    #[test]
    fn catalog_contains_expected_metrics() {
        let set = collect_metrics(&sample_input());
        let names: Vec<&str> = set.metrics.iter().map(|m| m.name.as_str()).collect();
        for expected in [
            "zeroshield_up",
            "zeroshield_info",
            "zeroshield_uptime_seconds",
            "zeroshield_scans_total",
            "zeroshield_threats_total",
            "zeroshield_findings_total",
            "zeroshield_quarantine_entries",
            "zeroshield_signatures_total",
            "zeroshield_rules_total",
            "zeroshield_clean_cache_entries",
            "zeroshield_watch_sessions",
            "zeroshield_watched_dirs",
            "zeroshield_net_rules",
            "zeroshield_procmon_processes",
            "zeroshield_events_total",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
        // One sample per severity.
        let severity_samples = set
            .metrics
            .iter()
            .filter(|m| m.name == "zeroshield_events_total")
            .count();
        assert_eq!(severity_samples, 2);
    }

    #[test]
    fn prometheus_text_shape() {
        let set = collect_metrics(&sample_input());
        let text = render_prometheus(&set);
        assert!(text.contains("# HELP zeroshield_up Whether the ZeroShield daemon is reachable (1) or not (0).\n# TYPE zeroshield_up gauge\nzeroshield_up 1\n"));
        assert!(text.contains("zeroshield_scans_total 12\n"));
        assert!(text.contains("zeroshield_info{version=\"0.1.0\"} 1\n"));
        assert!(text.contains("zeroshield_events_total{severity=\"critical\"} 2\n"));
        // HELP/TYPE for the multi-sample family appears exactly once.
        assert_eq!(text.matches("# TYPE zeroshield_events_total").count(), 1);
        // Every sample line ends with a newline.
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn prometheus_escapes_labels() {
        let mut input = sample_input();
        input.version = "1.0\"weird\\path\n".into();
        let text = render_prometheus(&collect_metrics(&input));
        assert!(text.contains("version=\"1.0\\\"weird\\\\path\\n\""));
    }

    #[test]
    fn down_daemon_reports_zero_up() {
        let mut input = sample_input();
        input.up = false;
        let text = render_prometheus(&collect_metrics(&input));
        assert!(text.contains("zeroshield_up 0\n"));
        assert!(text.contains("zeroshield_uptime_seconds 0\n"));
        // Storage-derived metrics stay truthful.
        assert!(text.contains("zeroshield_scans_total 12\n"));
    }

    #[test]
    fn journald_single_line() {
        let set = collect_metrics(&sample_input());
        let line = render_journald(&set);
        assert_eq!(line.lines().count(), 1);
        assert!(line.starts_with("zeroshield metrics "));
        assert!(line.contains("up=1"));
        assert!(line.contains("scans_total=12"));
        assert!(line.contains("events_total_severity_critical=2"));
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn metric_set_json_roundtrip() {
        let set = collect_metrics(&sample_input());
        let json = serde_json::to_string(&set).unwrap();
        let back: MetricSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.metrics.len(), set.metrics.len());
        let input = sample_input();
        let json = serde_json::to_string(&input).unwrap();
        let back: MetricsInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scans_total, input.scans_total);
        assert_eq!(back.events_by_severity.len(), 2);
    }
}

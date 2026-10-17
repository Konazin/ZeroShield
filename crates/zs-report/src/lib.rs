//! Reporting and metrics export for ZeroShield.
//!
//! [`report`] collects the persisted state (scans, findings, alerts,
//! quarantine) into a [`ReportData`] and renders it as JSON, CSV or a
//! self-contained HTML page. [`metrics`] builds a [`MetricSet`] from a
//! [`MetricsInput`] and renders it as Prometheus text (for the node_exporter
//! textfile collector) or as journald friendly lines.
//!
//! Both modules are pure: collection only reads a [`zs_core::storage::Storage`],
//! and rendering only formats data. The daemon serves `report.get` and
//! `metrics.get` from the same code the CLI uses in local mode.

pub mod metrics;
pub mod report;

pub use metrics::{
    collect_metrics, render_journald, render_prometheus, Metric, MetricKind, MetricSet,
    MetricsInput,
};
pub use report::{
    collect, hostname, render_csv, render_html, render_json, CsvSection, ReportData, ReportOptions,
    ReportSummary,
};

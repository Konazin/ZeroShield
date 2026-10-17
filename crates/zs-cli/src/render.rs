//! Terminal rendering helpers (colors, tables, truncation).

use zs_core::model::{Severity, Verdict};

pub fn is_tty(fd: i32) -> bool {
    // SAFETY: isatty is safe for any fd value.
    unsafe { libc::isatty(fd) == 1 }
}

#[derive(Clone, Copy)]
pub struct Style {
    pub color: bool,
}

impl Style {
    pub fn detect(no_color: bool) -> Self {
        let color = !no_color && std::env::var_os("NO_COLOR").is_none() && is_tty(1);
        Self { color }
    }

    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }

    pub fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }

    pub fn green(&self, s: &str) -> String {
        self.paint("32", s)
    }

    pub fn yellow(&self, s: &str) -> String {
        self.paint("33", s)
    }

    pub fn red(&self, s: &str) -> String {
        self.paint("31", s)
    }

    pub fn cyan(&self, s: &str) -> String {
        self.paint("36", s)
    }

    pub fn severity(&self, sev: Severity) -> String {
        match sev {
            Severity::Critical => self.paint("1;31", "CRITICAL"),
            Severity::High => self.paint("31", "HIGH"),
            Severity::Medium => self.paint("33", "MEDIUM"),
            Severity::Low => self.paint("36", "LOW"),
            Severity::Info => self.paint("2", "INFO"),
        }
    }

    pub fn verdict(&self, verdict: Verdict) -> String {
        match verdict {
            Verdict::Clean => self.green("clean"),
            Verdict::Suspicious => self.yellow("suspicious"),
            Verdict::Malicious => self.red("MALICIOUS"),
            Verdict::Error => self.red("error"),
        }
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('…');
    out
}

pub fn pad(s: &str, width: usize) -> String {
    let count = s.chars().count();
    if count >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - count))
    }
}

/// Print a simple left-aligned table.
pub fn print_table(style: &Style, headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
    }
    let header_line = headers
        .iter()
        .enumerate()
        .map(|(i, h)| pad(h, widths[i]))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{}", style.bold(header_line.trim_end()));
    let sep: String = widths
        .iter()
        .map(|w| "-".repeat(*w))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{}", style.dim(sep.trim_end()));
    for row in rows {
        let line = row
            .iter()
            .enumerate()
            .map(|(i, c)| pad(c, widths.get(i).copied().unwrap_or(0)))
            .collect::<Vec<_>>()
            .join("  ");
        println!("{}", line.trim_end());
    }
}

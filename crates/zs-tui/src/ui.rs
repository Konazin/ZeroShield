//! Rendering: header, tabs, per-tab tables and modal overlays.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Cell, Clear, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::Frame;

use zs_core::util::{format_ts, human_bytes};

use crate::app::{severity_style, App, Overlay, Tab};

const HELP: &str = "\
ZeroShield TUI

Tabs
  1..6, Tab / Shift+Tab      switch view

Navigation
  Up/Down or k/j             move selection
  PgUp/PgDn, Home/End        scroll
  Enter                      details for the selected row

Actions
  s                          scan a path (input box)
  x / X                      quarantine: restore / purge
  r                          refresh now
  p                          pause/resume the live follow
  q or Ctrl+C                quit
  ?                          this help
";

fn highlight() -> Style {
    Style::new().add_modifier(Modifier::REVERSED)
}

fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}

pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);
    render_header(frame, chunks[0], app);
    render_tabs(frame, chunks[1], app);
    render_body(frame, chunks[2], app);
    render_footer(frame, chunks[3], app);
    render_overlay(frame, area, app);
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let status = &app.status;
    let mut spans = vec![
        Span::styled(" ZeroShield ", Style::new().bold().fg(Color::Cyan)),
        Span::styled(
            format!(
                "v{} ",
                if status.version.is_empty() {
                    "-"
                } else {
                    &status.version
                }
            ),
            dim(),
        ),
    ];
    if app.connected {
        spans.push(Span::styled("● online ", Style::new().green()));
    } else {
        spans.push(Span::styled("● offline ", Style::new().red().bold()));
    }
    spans.push(Span::styled(
        format!(
            "scans {} · threats {} · quarantine {} · clean cache {} · watched {} dir(s)",
            status.scans,
            status.threats,
            status.quarantine_entries,
            status.clean_cache_entries,
            status.watched_dirs
        ),
        dim(),
    ));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, tab)| Line::from(format!(" {} {} ", i + 1, tab.title())))
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.tab_index())
        .highlight_style(Style::new().bold().fg(Color::Cyan))
        .divider(Span::styled("|", dim()));
    frame.render_widget(tabs, area);
}

fn render_body(frame: &mut Frame, area: Rect, app: &mut App) {
    let tab_index = app.tab_index();
    app.viewport_h[tab_index] = area.height;
    if !app.connected && app.status.version.is_empty() {
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "ZeroShield daemon is not reachable",
                Style::new().red().bold(),
            )),
            Line::from(""),
            Line::from(format!("waiting for {} …", app.socket)),
            Line::from(Span::styled(
                "start it with: systemctl start zeroshieldd   (or: sudo zeroshieldd)",
                dim(),
            )),
            Line::from(Span::styled("press q to quit, ? for help", dim())),
        ];
        frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), area);
        return;
    }
    match app.tab {
        Tab::Overview => render_overview(frame, area, app),
        Tab::Events => render_events(frame, area, app),
        Tab::Findings => render_findings(frame, area, app),
        Tab::Quarantine => render_quarantine(frame, area, app),
        Tab::Processes => render_processes(frame, area, app),
        Tab::Net => render_net(frame, area, app),
    }
}

fn render_overview(frame: &mut Frame, area: Rect, app: &mut App) {
    let split =
        Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).split(area);

    let status_rows: Vec<Row> = vec![
        ("version", app.status.version.clone()),
        ("pid", app.status.pid.to_string()),
        ("uptime", app.status.uptime_label()),
        ("socket", app.status.socket.clone()),
        ("scans", app.status.scans.to_string()),
        ("threats", app.status.threats.to_string()),
        ("rules", app.status.rules.to_string()),
        ("signatures", app.status.signatures.to_string()),
        ("quarantine", app.status.quarantine_entries.to_string()),
        ("clean cache", app.status.clean_cache_entries.to_string()),
        ("watch sessions", app.status.watch_sessions.to_string()),
        ("watched dirs", app.status.watched_dirs.to_string()),
        ("net rules", app.status.net_rules.to_string()),
    ]
    .into_iter()
    .map(|(key, value)| Row::new(vec![Cell::from(key), Cell::from(value)]))
    .collect();
    let status_table = Table::new(status_rows, [Constraint::Length(16), Constraint::Fill(1)])
        .block(Block::bordered().title(" Status "));
    frame.render_widget(status_table, split[0]);

    let header = Row::new(vec![
        Cell::from("module"),
        Cell::from("state"),
        Cell::from("detail"),
    ])
    .style(Style::new().bold());
    let module_rows: Vec<Row> = app
        .status
        .modules
        .iter()
        .map(|module| {
            let (text, style) = if module.healthy {
                ("ok", Style::new().green())
            } else {
                ("fail", Style::new().red().bold())
            };
            Row::new(vec![
                Cell::from(module.name.clone()),
                Cell::from(Span::styled(text, style)),
                Cell::from(module.detail.clone()),
            ])
        })
        .collect();
    let modules = Table::new(
        module_rows,
        [
            Constraint::Length(12),
            Constraint::Length(6),
            Constraint::Fill(1),
        ],
    )
    .header(header)
    .block(Block::bordered().title(" Modules "))
    .highlight_symbol(">> ")
    .row_highlight_style(highlight());
    frame.render_stateful_widget(modules, split[1], app.state_mut());
}

fn render_events(frame: &mut Frame, area: Rect, app: &mut App) {
    let header = Row::new(vec![
        Cell::from("when"),
        Cell::from("kind"),
        Cell::from("severity"),
        Cell::from("payload"),
    ])
    .style(Style::new().bold());
    let rows: Vec<Row> = app
        .events
        .iter()
        .map(|event| {
            Row::new(vec![
                Cell::from(format_ts(event.ts)),
                Cell::from(event.kind.clone()),
                Cell::from(Span::styled(
                    event.severity.as_str(),
                    severity_style(event.severity),
                )),
                Cell::from(one_line(&event.payload, 100)),
            ])
        })
        .collect();
    let title = if app.stream_paused {
        format!(" Events (paused, +{} new) ", app.unread_live)
    } else {
        " Events — live ".to_string()
    };
    let table = Table::new(
        rows,
        [
            Constraint::Length(19),
            Constraint::Length(16),
            Constraint::Length(8),
            Constraint::Fill(1),
        ],
    )
    .header(header)
    .block(Block::bordered().title(title))
    .highlight_symbol(">> ")
    .row_highlight_style(highlight());
    frame.render_stateful_widget(table, area, app.state_mut());
}

fn render_findings(frame: &mut Frame, area: Rect, app: &mut App) {
    let header = Row::new(vec![
        Cell::from("path"),
        Cell::from("score"),
        Cell::from("severity"),
        Cell::from("verdict"),
        Cell::from("quar."),
        Cell::from("detections"),
    ])
    .style(Style::new().bold());
    let rows: Vec<Row> = app
        .findings
        .iter()
        .map(|finding| {
            Row::new(vec![
                Cell::from(finding.path.clone()),
                Cell::from(finding.score.to_string()),
                Cell::from(Span::styled(
                    finding.severity.as_str(),
                    severity_style(finding.severity),
                )),
                Cell::from(finding.verdict.as_str().to_string()),
                Cell::from(if finding.quarantined { "yes" } else { "-" }),
                Cell::from(detections_brief(finding)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Fill(2),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(11),
            Constraint::Length(6),
            Constraint::Fill(3),
        ],
    )
    .header(header)
    .block(Block::bordered().title(format!(" Findings ({} shown) ", app.findings.len())))
    .highlight_symbol(">> ")
    .row_highlight_style(highlight());
    frame.render_stateful_widget(table, area, app.state_mut());
}

fn render_quarantine(frame: &mut Frame, area: Rect, app: &mut App) {
    let header = Row::new(vec![
        Cell::from("id"),
        Cell::from("when"),
        Cell::from("original path"),
        Cell::from("size"),
        Cell::from("status"),
    ])
    .style(Style::new().bold());
    let rows: Vec<Row> = app
        .quarantine
        .iter()
        .map(|entry| {
            let (status, style) = if entry.restored {
                ("restored", Style::new().green())
            } else {
                ("held", Style::new().red().bold())
            };
            Row::new(vec![
                Cell::from(entry.id.to_string()),
                Cell::from(format_ts(entry.ts)),
                Cell::from(entry.original_path.clone()),
                Cell::from(human_bytes(entry.size)),
                Cell::from(Span::styled(status, style)),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(19),
            Constraint::Fill(2),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(Block::bordered().title(" Quarantine (x restore · X purge) "))
    .highlight_symbol(">> ")
    .row_highlight_style(highlight());
    frame.render_stateful_widget(table, area, app.state_mut());
}

fn render_processes(frame: &mut Frame, area: Rect, app: &mut App) {
    let header = Row::new(vec![
        Cell::from("pid"),
        Cell::from("score"),
        Cell::from("severity"),
        Cell::from("name"),
        Cell::from("cmdline"),
        Cell::from("reasons"),
    ])
    .style(Style::new().bold());
    let rows: Vec<Row> = app
        .processes
        .iter()
        .map(|proc_| {
            Row::new(vec![
                Cell::from(proc_.pid.to_string()),
                Cell::from(proc_.score.to_string()),
                Cell::from(Span::styled(
                    proc_.severity.as_str(),
                    severity_style(proc_.severity),
                )),
                Cell::from(proc_.name.clone()),
                Cell::from(truncate(&proc_.cmdline.join(" "), 70)),
                Cell::from(proc_.reasons.len().to_string()),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Fill(2),
            Constraint::Length(7),
        ],
    )
    .header(header)
    .block(Block::bordered().title(format!(" Processes ({} visible) ", app.processes.len())))
    .highlight_symbol(">> ")
    .row_highlight_style(highlight());
    frame.render_stateful_widget(table, area, app.state_mut());
}

fn render_net(frame: &mut Frame, area: Rect, app: &mut App) {
    let header =
        Row::new(vec![Cell::from("field"), Cell::from("value")]).style(Style::new().bold());
    let rows: Vec<Row> = app
        .net_lines
        .iter()
        .map(|(key, value)| Row::new(vec![Cell::from(key.clone()), Cell::from(value.clone())]))
        .collect();
    let table = Table::new(rows, [Constraint::Length(28), Constraint::Fill(1)])
        .header(header)
        .block(Block::bordered().title(" Net (IPS) "))
        .highlight_symbol(">> ")
        .row_highlight_style(highlight());
    frame.render_stateful_widget(table, area, app.state_mut());
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    // While something is happening (scan, message, note) the hints shrink so
    // the important text has room to render.
    let busy = app.message.is_some() || app.scan_running.is_some() || app.scan_note.is_some();
    let hints = if busy {
        " q · Tab · Enter · r · p · s · ? "
    } else if app.tab == Tab::Quarantine {
        " q quit · Tab switch · Enter details · x restore · X purge · r refresh · p pause · s scan · ? help"
    } else {
        " q quit · Tab switch · Enter details · r refresh · p pause · s scan · ? help"
    };
    let mut spans = vec![Span::styled(hints, dim())];
    if app.stream_paused {
        spans.push(Span::styled(
            format!(" PAUSED +{} ", app.unread_live),
            Style::new().yellow().bold(),
        ));
    }
    if let Some(target) = &app.scan_running {
        spans.push(Span::styled(
            format!(" scanning {target} "),
            Style::new().cyan(),
        ));
    }
    if let Some((text, ok)) = &app.message {
        spans.push(Span::styled(
            format!(" {text} "),
            if *ok {
                Style::new().green()
            } else {
                Style::new().red()
            },
        ));
    } else if let Some(note) = &app.scan_note {
        spans.push(Span::styled(format!(" {note} "), dim()));
    }
    if let Some(kind) = &app.last_event {
        spans.push(Span::styled(format!(" last: {kind} "), dim()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_overlay(frame: &mut Frame, area: Rect, app: &App) {
    match &app.overlay {
        Overlay::None => {}
        Overlay::Help => {
            let popup = centered(area, 62, 80);
            if popup.height > 1 {
                frame.render_widget(Clear, popup);
                let help = Paragraph::new(HELP)
                    .block(Block::bordered().title(" Help "))
                    .wrap(Wrap { trim: false });
                frame.render_widget(help, popup);
            }
        }
        Overlay::Details {
            title,
            lines,
            scroll,
        } => {
            let popup = centered(area, 84, 80);
            if popup.height > 1 {
                frame.render_widget(Clear, popup);
                let text = Text::from(
                    lines
                        .iter()
                        .map(|line| Line::from(line.clone()))
                        .collect::<Vec<Line>>(),
                );
                let details = Paragraph::new(text)
                    .block(Block::bordered().title(format!(" {title} ")))
                    .scroll((*scroll, 0))
                    .wrap(Wrap { trim: false });
                frame.render_widget(details, popup);
            }
        }
        Overlay::Confirm { prompt, .. } => {
            let popup = centered_fixed(area, 64, 5);
            if popup.height > 1 {
                frame.render_widget(Clear, popup);
                let text = vec![
                    Line::from(prompt.clone()),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("[y] confirm", Style::new().red().bold()),
                        Span::raw("    "),
                        Span::styled("[n]/Esc cancel", dim()),
                    ]),
                ];
                let confirm = Paragraph::new(text).block(
                    Block::bordered()
                        .title(" Confirm ")
                        .border_style(Style::new().red()),
                );
                frame.render_widget(confirm, popup);
            }
        }
        Overlay::ScanInput { buffer } => {
            let popup = centered_fixed(area, 70, 3);
            if popup.height > 1 {
                frame.render_widget(Clear, popup);
                let line = Line::from(vec![
                    Span::styled("scan path: ", Style::new().bold()),
                    Span::raw(buffer.clone()),
                    Span::styled("▏", Style::new().yellow()),
                ]);
                let input = Paragraph::new(line).block(
                    Block::bordered()
                        .title(" Scan ")
                        .border_style(Style::new().cyan()),
                );
                frame.render_widget(input, popup);
            }
        }
    }
}

fn centered(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);
    let horizontal = Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1]);
    horizontal[1]
}

fn centered_fixed(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

fn one_line(value: &serde_json::Value, max: usize) -> String {
    truncate(&value.to_string(), max)
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn detections_brief(finding: &zs_core::model::Finding) -> String {
    truncate(
        &finding
            .detections
            .iter()
            .map(|d| format!("{} (+{})", d.name, d.score))
            .collect::<Vec<_>>()
            .join("; "),
        80,
    )
}

/// Filename-only styles for tests.
#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn draw(app: &mut App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal.draw(|frame| render(frame, app)).expect("draw");
        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                let cell = &buffer.content[y as usize * buffer.area.width as usize + x as usize];
                out.push_str(cell.symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn renders_every_tab_without_panicking() {
        let mut app = crate::fixtures::full_app();
        for tab in Tab::ALL {
            app.set_tab(tab);
            let text = draw(&mut app, 110, 30);
            assert!(
                text.contains(tab.title()),
                "tab {} not rendered: {text}",
                tab.title()
            );
        }
    }

    #[test]
    fn renders_overlays_without_panicking() {
        let mut app = crate::fixtures::full_app();
        app.overlay = Overlay::Help;
        assert!(draw(&mut app, 100, 30).contains("ZeroShield TUI"));
        app.overlay = Overlay::Details {
            title: "event".into(),
            lines: vec!["line one".into(), "line two".into()],
            scroll: 0,
        };
        assert!(draw(&mut app, 100, 30).contains("line one"));
        app.overlay = Overlay::Confirm {
            prompt: "Restore /tmp/x?".into(),
            action: crate::app::Action::Quit,
        };
        assert!(draw(&mut app, 100, 30).contains("Restore /tmp/x?"));
        app.overlay = Overlay::ScanInput {
            buffer: "/home".into(),
        };
        assert!(draw(&mut app, 100, 30).contains("scan path: /home"));
    }

    #[test]
    fn renders_tiny_terminal_without_panicking() {
        let mut app = crate::fixtures::full_app();
        for (w, h) in [(1, 1), (20, 5), (40, 10), (5, 40)] {
            let _ = draw(&mut app, w, h);
        }
    }

    #[test]
    fn offline_splash_when_never_connected() {
        let mut app = App::new("test.sock".into());
        app.connected = false;
        let text = draw(&mut app, 100, 30);
        assert!(text.contains("daemon is not reachable"));
        assert!(text.contains("test.sock"));
    }

    #[test]
    fn findings_tab_shows_fixture_path() {
        let mut app = crate::fixtures::full_app();
        app.set_tab(Tab::Findings);
        let text = draw(&mut app, 130, 30);
        assert!(text.contains("/tmp/eicar.com"), "got: {text}");
        assert!(text.contains("critical"));
    }
}

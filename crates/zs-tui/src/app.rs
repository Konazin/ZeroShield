//! TUI application state: data model, key handling and actions.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;
use serde::Serialize;
use serde_json::Value;

use zs_core::model::{Finding, ProcInfo, QuarantineEntry, Severity, StoredEvent};
use zs_core::util::{format_ts, human_duration};

/// The visible tabs, in order. The indices are stable (used by the task
/// poller to know which sections to refresh).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Events,
    Findings,
    Quarantine,
    Processes,
    Net,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Overview,
        Tab::Events,
        Tab::Findings,
        Tab::Quarantine,
        Tab::Processes,
        Tab::Net,
    ];

    pub fn index(self) -> usize {
        match self {
            Tab::Overview => 0,
            Tab::Events => 1,
            Tab::Findings => 2,
            Tab::Quarantine => 3,
            Tab::Processes => 4,
            Tab::Net => 5,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Events => "Events",
            Tab::Findings => "Findings",
            Tab::Quarantine => "Quarantine",
            Tab::Processes => "Processes",
            Tab::Net => "Net",
        }
    }

    pub fn next(self) -> Tab {
        Tab::ALL[(self.index() + 1) % Tab::ALL.len()]
    }

    pub fn prev(self) -> Tab {
        Tab::ALL[(self.index() + Tab::ALL.len() - 1) % Tab::ALL.len()]
    }
}

/// One engine module, as shown in the overview.
#[derive(Debug, Clone, Default)]
pub struct ModuleView {
    pub name: String,
    pub description: String,
    pub healthy: bool,
    pub detail: String,
    pub capabilities: Vec<String>,
}

/// Parsed daemon status (fields we display).
#[derive(Debug, Clone, Default)]
pub struct StatusView {
    pub version: String,
    pub pid: u64,
    pub uptime_secs: u64,
    pub socket: String,
    pub scans: u64,
    pub threats: u64,
    pub rules: usize,
    pub signatures: u64,
    pub quarantine_entries: u64,
    pub clean_cache_entries: u64,
    pub watch_sessions: u64,
    pub watched_dirs: u64,
    pub net_rules: u64,
    pub modules: Vec<ModuleView>,
}

impl StatusView {
    /// Parse the `status` RPC result. Missing fields default to zero/empty.
    pub fn from_value(value: &Value) -> Self {
        let num = |key: &str| value.get(key).and_then(Value::as_u64).unwrap_or(0);
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let modules = value
            .get("modules")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|m| ModuleView {
                        name: m
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("?")
                            .to_string(),
                        description: m
                            .get("description")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        healthy: m.get("healthy").and_then(Value::as_bool).unwrap_or(false),
                        detail: m
                            .get("detail")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        capabilities: m
                            .get("capabilities")
                            .and_then(Value::as_array)
                            .map(|c| {
                                c.iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_string)
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            version: text("version"),
            pid: num("pid"),
            uptime_secs: num("uptime_secs"),
            socket: text("socket"),
            scans: num("scans"),
            threats: num("threats"),
            rules: num("rules") as usize,
            signatures: num("signatures"),
            quarantine_entries: num("quarantine_entries"),
            clean_cache_entries: num("clean_cache_entries"),
            watch_sessions: num("watch_sessions"),
            watched_dirs: num("watched_dirs"),
            net_rules: num("net_rules"),
            modules,
        }
    }

    pub fn uptime_label(&self) -> String {
        human_duration(self.uptime_secs.saturating_mul(1000))
    }
}

/// Data flowing from the background tasks into the UI.
#[derive(Debug)]
pub enum Update {
    Connected(bool),
    Status(Box<StatusView>),
    Events(Vec<StoredEvent>),
    Findings(Vec<Finding>),
    Quarantine(Vec<QuarantineEntry>),
    Processes(Vec<ProcInfo>),
    Net(Vec<(String, String)>),
    /// A daemon-wide broadcast event arrived (kind string).
    LiveEvent(String),
    /// Scan progress text (empty clears it).
    ScanNote(String),
    /// The scan started from the TUI finished (successfully or not).
    ScanFinished,
    /// A one-off message for the footer.
    Message {
        text: String,
        ok: bool,
    },
}

/// An action the UI asks the run loop to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Quit,
    Refresh,
    Scan(String),
    RestoreQuarantine(i64),
    PurgeQuarantine(i64),
}

/// Modal overlay.
#[derive(Debug, Default)]
pub enum Overlay {
    #[default]
    None,
    Help,
    Details {
        title: String,
        lines: Vec<String>,
        scroll: u16,
    },
    Confirm {
        prompt: String,
        action: Action,
    },
    ScanInput {
        buffer: String,
    },
}

pub struct App {
    pub socket: String,
    pub should_quit: bool,
    pub connected: bool,
    pub tab: Tab,
    pub status: StatusView,
    pub events: Vec<StoredEvent>,
    pub findings: Vec<Finding>,
    pub quarantine: Vec<QuarantineEntry>,
    pub processes: Vec<ProcInfo>,
    pub net_lines: Vec<(String, String)>,
    pub overlay: Overlay,
    pub tables: Vec<TableState>,
    /// Last known body height per tab (used by PgUp/PgDn).
    pub viewport_h: Vec<u16>,
    pub stream_paused: bool,
    pub unread_live: u64,
    pub last_event: Option<String>,
    pub message: Option<(String, bool)>,
    pub scan_running: Option<String>,
    pub scan_note: Option<String>,
    pub tick: u64,
}

impl App {
    pub fn new(socket: String) -> Self {
        Self {
            socket,
            should_quit: false,
            connected: false,
            tab: Tab::Overview,
            status: StatusView::default(),
            events: Vec::new(),
            findings: Vec::new(),
            quarantine: Vec::new(),
            processes: Vec::new(),
            net_lines: Vec::new(),
            overlay: Overlay::None,
            tables: (0..Tab::ALL.len()).map(|_| TableState::default()).collect(),
            viewport_h: vec![20; Tab::ALL.len()],
            stream_paused: false,
            unread_live: 0,
            last_event: None,
            message: None,
            scan_running: None,
            scan_note: None,
            tick: 0,
        }
    }

    pub fn tab_index(&self) -> usize {
        self.tab.index()
    }

    pub fn state_mut(&mut self) -> &mut TableState {
        let idx = self.tab_index();
        &mut self.tables[idx]
    }

    pub fn tab_len(&self) -> usize {
        match self.tab {
            Tab::Overview => self.status.modules.len(),
            Tab::Events => self.events.len(),
            Tab::Findings => self.findings.len(),
            Tab::Quarantine => self.quarantine.len(),
            Tab::Processes => self.processes.len(),
            Tab::Net => self.net_lines.len(),
        }
    }

    /// Currently selected row of the active tab (clamped to the data).
    pub fn selected(&self) -> Option<usize> {
        let len = self.tab_len();
        if len == 0 {
            return None;
        }
        let state = &self.tables[self.tab_index()];
        Some(state.selected().unwrap_or(0).min(len - 1))
    }

    pub fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.clamp_tab(tab.index());
    }

    pub fn apply(&mut self, update: Update) {
        match update {
            Update::Connected(connected) => {
                if connected != self.connected {
                    self.connected = connected;
                    if connected {
                        self.message = Some(("connected to the daemon".into(), true));
                    }
                }
            }
            Update::Status(status) => self.status = *status,
            Update::Events(events) => {
                if !self.stream_paused {
                    self.events = events;
                    self.unread_live = 0;
                }
            }
            Update::Findings(findings) => self.findings = findings,
            Update::Quarantine(entries) => self.quarantine = entries,
            Update::Processes(processes) => self.processes = processes,
            Update::Net(lines) => self.net_lines = lines,
            Update::LiveEvent(kind) => {
                self.last_event = Some(kind);
                if self.stream_paused {
                    self.unread_live += 1;
                }
            }
            Update::ScanNote(note) => {
                self.scan_note = if note.is_empty() { None } else { Some(note) };
            }
            Update::ScanFinished => {
                self.scan_running = None;
                self.scan_note = None;
            }
            Update::Message { text, ok } => self.message = Some((text, ok)),
        }
        self.clamp_all();
    }

    pub(crate) fn clamp_all(&mut self) {
        for idx in 0..Tab::ALL.len() {
            self.clamp_tab(idx);
        }
    }

    fn clamp_tab(&mut self, idx: usize) {
        let len = {
            let saved = self.tab;
            self.tab = Tab::ALL[idx];
            let len = self.tab_len();
            self.tab = saved;
            len
        };
        let state = &mut self.tables[idx];
        match len {
            0 => state.select(None),
            n => {
                let current = state.selected().unwrap_or(0).min(n - 1);
                state.select(Some(current));
            }
        }
    }

    fn page_step(&self) -> usize {
        let h = self.viewport_h[self.tab_index()];
        (h.saturating_sub(2)).max(1) as usize
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.tab_len();
        if len == 0 {
            self.state_mut().select(None);
            return;
        }
        let current = self.state_mut().selected().unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, len as isize - 1);
        self.state_mut().select(Some(next as usize));
    }

    fn select_index(&mut self, index: usize) {
        let len = self.tab_len();
        if len == 0 {
            self.state_mut().select(None);
        } else {
            self.state_mut().select(Some(index.min(len - 1)));
        }
    }

    fn selected_quarantine(&self) -> Option<(i64, String)> {
        let idx = self.selected()?;
        self.quarantine
            .get(idx)
            .map(|entry| (entry.id, entry.original_path.clone()))
    }

    fn open_details(&mut self) {
        let idx = match self.selected() {
            Some(idx) => idx,
            None => return,
        };
        let details = match self.tab {
            Tab::Overview => self.status.modules.get(idx).map(|module| {
                let mut lines = vec![
                    format!("module:      {}", module.name),
                    format!("description: {}", module.description),
                    format!("healthy:     {}", module.healthy),
                    format!("state:       {}", module.detail),
                ];
                if !module.capabilities.is_empty() {
                    lines.push(format!("capabilities: {}", module.capabilities.join(", ")));
                }
                (module.name.clone(), lines)
            }),
            Tab::Events => self.events.get(idx).map(|event| {
                let mut lines = vec![
                    format!("id:       {}", event.id),
                    format!("when:     {}", format_ts(event.ts)),
                    format!("kind:     {}", event.kind),
                    format!("severity: {}", event.severity.as_str()),
                    String::new(),
                ];
                lines.extend(pretty(&event.payload));
                (event.kind.clone(), lines)
            }),
            Tab::Findings => self
                .findings
                .get(idx)
                .map(|finding| (finding.path.clone(), pretty(finding))),
            Tab::Quarantine => self
                .quarantine
                .get(idx)
                .map(|entry| (format!("#{} {}", entry.id, entry.file_name), pretty(entry))),
            Tab::Processes => self
                .processes
                .get(idx)
                .map(|proc_| (format!("pid {} {}", proc_.pid, proc_.name), pretty(proc_))),
            Tab::Net => self
                .net_lines
                .get(idx)
                .map(|(key, value)| (key.clone(), vec![value.clone()])),
        };
        if let Some((title, lines)) = details {
            self.overlay = Overlay::Details {
                title,
                lines,
                scroll: 0,
            };
        }
    }

    /// Handle a key press. Returns an [`Action`] when the run loop must do
    /// something outside the UI (network calls, quitting, ...).
    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        // Modal overlays capture all keys first.
        match std::mem::take(&mut self.overlay) {
            Overlay::None => {}
            Overlay::Help => return None, // any key closes the help
            Overlay::Details {
                title,
                lines,
                mut scroll,
            } => {
                let max_scroll = lines.len().saturating_sub(1) as u16;
                match key.code {
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => return None,
                    KeyCode::Up => scroll = scroll.saturating_sub(1),
                    KeyCode::Down => scroll = (scroll + 1).min(max_scroll),
                    KeyCode::PageUp => scroll = scroll.saturating_sub(10),
                    KeyCode::PageDown => scroll = (scroll + 10).min(max_scroll),
                    _ => {}
                }
                self.overlay = Overlay::Details {
                    title,
                    lines,
                    scroll,
                };
                return None;
            }
            Overlay::Confirm { prompt, action } => {
                match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                        return Some(action);
                    }
                    KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => return None,
                    _ => {}
                }
                self.overlay = Overlay::Confirm { prompt, action };
                return None;
            }
            Overlay::ScanInput { mut buffer } => {
                match key.code {
                    KeyCode::Enter => {
                        let target = buffer.trim().to_string();
                        if !target.is_empty() {
                            return Some(Action::Scan(target));
                        }
                        return None;
                    }
                    KeyCode::Esc => return None,
                    KeyCode::Backspace => {
                        buffer.pop();
                    }
                    KeyCode::Char(c) if !ctrl => buffer.push(c),
                    _ => {}
                }
                self.overlay = Overlay::ScanInput { buffer };
                return None;
            }
        }

        // Normal mode.
        if ctrl && key.code == KeyCode::Char('c') {
            return Some(Action::Quit);
        }
        match key.code {
            KeyCode::Char('q') => return Some(Action::Quit),
            KeyCode::Char('?') => self.overlay = Overlay::Help,
            KeyCode::Char('r') => return Some(Action::Refresh),
            KeyCode::Char('p') => {
                self.stream_paused = !self.stream_paused;
                if !self.stream_paused {
                    return Some(Action::Refresh);
                }
            }
            KeyCode::Char('s') if self.connected => {
                self.overlay = Overlay::ScanInput {
                    buffer: String::new(),
                };
            }
            KeyCode::Char(c @ '1'..='6') => {
                let idx = c as usize - '1' as usize;
                self.set_tab(Tab::ALL[idx]);
            }
            KeyCode::Tab => self.set_tab(self.tab.next()),
            KeyCode::BackTab => self.set_tab(self.tab.prev()),
            KeyCode::Char('x') if self.tab == Tab::Quarantine => {
                if let Some((id, path)) = self.selected_quarantine() {
                    self.overlay = Overlay::Confirm {
                        prompt: format!("Restore {path}?"),
                        action: Action::RestoreQuarantine(id),
                    };
                }
            }
            KeyCode::Char('X') if self.tab == Tab::Quarantine => {
                if let Some((id, path)) = self.selected_quarantine() {
                    self.overlay = Overlay::Confirm {
                        prompt: format!("Permanently purge {path}?"),
                        action: Action::PurgeQuarantine(id),
                    };
                }
            }
            KeyCode::Enter => self.open_details(),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => {
                let step = self.page_step() as isize;
                self.move_selection(-step);
            }
            KeyCode::PageDown => {
                let step = self.page_step() as isize;
                self.move_selection(step);
            }
            KeyCode::Home => self.select_index(0),
            KeyCode::End => self.select_index(usize::MAX),
            _ => {}
        }
        None
    }
}

fn pretty<T: Serialize>(value: &T) -> Vec<String> {
    serde_json::to_string_pretty(value)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

/// Severity color shared by all views.
pub fn severity_style(severity: Severity) -> ratatui::style::Style {
    use ratatui::style::{Color, Modifier, Style};
    match severity {
        Severity::Critical => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::High => Style::new().fg(Color::Red),
        Severity::Medium => Style::new().fg(Color::Yellow),
        Severity::Low => Style::new().fg(Color::Blue),
        Severity::Info => Style::new().fg(Color::Gray),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn status_parses_snake_case_fields() {
        let status = crate::fixtures::status();
        assert_eq!(status.version, "0.1.0-test");
        assert_eq!(status.pid, 1234);
        assert_eq!(status.uptime_secs, 90);
        assert_eq!(status.scans, 4);
        assert_eq!(status.threats, 2);
        assert_eq!(status.rules, 12);
        assert_eq!(status.signatures, 3);
        assert_eq!(status.quarantine_entries, 1);
        assert_eq!(status.clean_cache_entries, 7);
        assert_eq!(status.watch_sessions, 1);
        assert_eq!(status.watched_dirs, 2);
        assert_eq!(status.modules.len(), 2);
        assert!(status.modules[0].healthy);
        assert_eq!(status.modules[0].capabilities.len(), 2);
    }

    #[test]
    fn tab_switching_wraps() {
        let mut app = crate::fixtures::full_app();
        assert_eq!(app.tab, Tab::Overview);
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.tab, Tab::Events);
        app.on_key(key(KeyCode::BackTab));
        assert_eq!(app.tab, Tab::Overview);
        app.on_key(key(KeyCode::Char('6')));
        assert_eq!(app.tab, Tab::Net);
        app.on_key(key(KeyCode::Tab));
        assert_eq!(app.tab, Tab::Overview);
    }

    #[test]
    fn selection_clamps_to_data() {
        let mut app = crate::fixtures::full_app();
        // The overview has two modules.
        assert_eq!(app.selected(), Some(0));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.selected(), Some(1));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.selected(), Some(1));
        app.on_key(key(KeyCode::Home));
        assert_eq!(app.selected(), Some(0));
        app.on_key(key(KeyCode::Up));
        assert_eq!(app.selected(), Some(0));
        app.on_key(key(KeyCode::End));
        assert_eq!(app.selected(), Some(1));
    }

    #[test]
    fn selection_is_clamped_when_data_shrinks() {
        let mut app = crate::fixtures::full_app();
        app.set_tab(Tab::Events);
        app.apply(Update::Events(vec![
            crate::fixtures::event(),
            crate::fixtures::event(),
            crate::fixtures::event(),
        ]));
        app.on_key(key(KeyCode::End));
        assert_eq!(app.selected(), Some(2));
        app.apply(Update::Events(vec![crate::fixtures::event()]));
        assert_eq!(app.selected(), Some(0));
    }

    #[test]
    fn empty_tab_has_no_selection() {
        let mut app = crate::fixtures::full_app();
        app.set_tab(Tab::Findings);
        assert!(app.selected().is_some());
        app.apply(Update::Findings(vec![]));
        assert_eq!(app.selected(), None);
        assert!(app.on_key(key(KeyCode::Enter)).is_none());
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn quit_keys() {
        let mut app = crate::fixtures::full_app();
        assert_eq!(app.on_key(key(KeyCode::Char('q'))), Some(Action::Quit));
        assert_eq!(
            app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(Action::Quit)
        );
    }

    #[test]
    fn pause_toggles_and_unpause_refreshes() {
        let mut app = crate::fixtures::full_app();
        assert_eq!(app.on_key(key(KeyCode::Char('p'))), None);
        assert!(app.stream_paused);
        app.apply(Update::LiveEvent("scan_finding".into()));
        assert_eq!(app.unread_live, 1);
        // While paused the events list stays frozen.
        app.apply(Update::Events(vec![]));
        assert_eq!(app.events.len(), 1);
        assert_eq!(app.on_key(key(KeyCode::Char('p'))), Some(Action::Refresh));
        assert!(!app.stream_paused);
        app.apply(Update::Events(vec![]));
        assert_eq!(app.events.len(), 0);
        assert_eq!(app.unread_live, 0);
    }

    #[test]
    fn confirm_flow_for_quarantine() {
        let mut app = crate::fixtures::full_app();
        app.set_tab(Tab::Quarantine);
        app.on_key(key(KeyCode::Char('x')));
        assert!(matches!(app.overlay, Overlay::Confirm { .. }));
        // Unrelated keys keep the dialog open.
        app.on_key(key(KeyCode::Char('z')));
        assert!(matches!(app.overlay, Overlay::Confirm { .. }));
        let action = app.on_key(key(KeyCode::Char('y')));
        assert_eq!(action, Some(Action::RestoreQuarantine(1)));
        assert!(matches!(app.overlay, Overlay::None));
        // Cancel path.
        app.on_key(key(KeyCode::Char('X')));
        assert!(matches!(app.overlay, Overlay::Confirm { .. }));
        app.on_key(key(KeyCode::Esc));
        assert!(matches!(app.overlay, Overlay::None));
        // The x/X keys do nothing outside the quarantine tab.
        app.set_tab(Tab::Events);
        app.on_key(key(KeyCode::Char('x')));
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn scan_input_flow() {
        let mut app = crate::fixtures::full_app();
        app.on_key(key(KeyCode::Char('s')));
        assert!(matches!(app.overlay, Overlay::ScanInput { .. }));
        for c in "/tmp/z".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Backspace));
        let action = app.on_key(key(KeyCode::Enter));
        assert_eq!(action, Some(Action::Scan("/tmp/".into())));
        assert!(matches!(app.overlay, Overlay::None));
        // Esc cancels without an action; empty input does nothing.
        app.on_key(key(KeyCode::Char('s')));
        assert_eq!(app.on_key(key(KeyCode::Esc)), None);
        assert!(matches!(app.overlay, Overlay::None));
        app.on_key(key(KeyCode::Char('s')));
        assert_eq!(app.on_key(key(KeyCode::Enter)), None);
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn scan_key_requires_connection() {
        let mut app = crate::fixtures::full_app();
        app.connected = false;
        app.on_key(key(KeyCode::Char('s')));
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn details_open_and_close() {
        let mut app = crate::fixtures::full_app();
        app.set_tab(Tab::Findings);
        app.on_key(key(KeyCode::Enter));
        match &app.overlay {
            Overlay::Details { title, lines, .. } => {
                assert!(title.contains("eicar"));
                assert!(lines.iter().any(|line| line.contains("eicar")));
            }
            other => panic!("expected details, got {other:?}"),
        }
        app.on_key(key(KeyCode::Esc));
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn help_opens_and_any_key_closes() {
        let mut app = crate::fixtures::full_app();
        app.on_key(key(KeyCode::Char('?')));
        assert!(matches!(app.overlay, Overlay::Help));
        app.on_key(key(KeyCode::Char('x')));
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn scan_finished_clears_running_state() {
        let mut app = crate::fixtures::full_app();
        app.scan_running = Some("/tmp".into());
        app.apply(Update::ScanFinished);
        assert!(app.scan_running.is_none());
        assert!(app.scan_note.is_none());
    }

    #[test]
    fn refresh_action_on_demand() {
        let mut app = crate::fixtures::full_app();
        assert_eq!(app.on_key(key(KeyCode::Char('r'))), Some(Action::Refresh));
    }
}

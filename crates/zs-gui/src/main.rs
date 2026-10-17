//! ZeroShield GTK4 application.
//!
//! The GUI is a thin client of `zeroshieldd`: all work happens in the daemon
//! and results arrive over the unix socket. The UI therefore starts instantly
//! and shows live scan progress from the event stream.
//!
//! Build requirement (not part of the default workspace build):
//!   Debian: sudo apt install libgtk-4-dev libadwaita-1-dev
//!   Arch:   sudo pacman -S gtk4 libadwaita
//!   cargo run -p zs-gui

use std::path::PathBuf;

use adw::prelude::*;
use gtk::glib;
use gtk::Orientation;

use zs_core::event::Event;
use zs_core::paths::Paths;
use zs_ipc::protocol::methods;

/// Messages from the worker thread to the UI.
#[derive(Debug)]
enum Msg {
    Daemon(serde_json::Value),
    ScanStarted(String),
    ScanProgress {
        files: u64,
        bytes: u64,
        path: String,
    },
    Finding(serde_json::Value),
    ScanFinished(serde_json::Value),
    Quarantine(Vec<serde_json::Value>),
    NetStatus(serde_json::Value),
    NetAudit(Vec<serde_json::Value>),
    Error(String),
}

/// Commands from the UI to the worker thread.
#[derive(Debug)]
enum Cmd {
    RefreshStatus,
    Scan(PathBuf),
    RefreshQuarantine,
    NetStatus,
    NetAudit(String),
}

fn main() -> glib::ExitCode {
    let app = adw::Application::builder()
        .application_id("io.github.konazin.zeroshield")
        .build();
    app.connect_activate(build_ui);
    app.run()
}

fn build_ui(app: &adw::Application) {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("ZeroShield")
        .default_width(1040)
        .default_height(700)
        .build();

    let stack = gtk::Stack::new();
    let switcher = gtk::StackSwitcher::builder().stack(&stack).build();
    let header = gtk::HeaderBar::new();
    header.set_title_widget(Some(&switcher));
    window.set_titlebar(Some(&header));

    // ---------------------------------------------------------------- pages
    let status_page = gtk::Box::new(Orientation::Vertical, 12);
    status_page.set_margin_top(18);
    status_page.set_margin_bottom(18);
    status_page.set_margin_start(18);
    status_page.set_margin_end(18);
    let status_label = gtk::Label::new(Some("connecting to the daemon…"));
    status_label.set_xalign(0.0);
    status_label.set_selectable(true);
    status_label.set_wrap(true);
    let status_refresh = gtk::Button::with_label("Refresh");
    status_page.append(&status_refresh);
    status_page.append(&status_label);

    let scan_page = gtk::Box::new(Orientation::Vertical, 12);
    scan_page.set_margin_top(18);
    scan_page.set_margin_bottom(18);
    scan_page.set_margin_start(18);
    scan_page.set_margin_end(18);
    let scan_buttons = gtk::Box::new(Orientation::Horizontal, 8);
    let scan_file = gtk::Button::with_label("Scan file…");
    let scan_folder = gtk::Button::with_label("Scan folder…");
    scan_buttons.append(&scan_file);
    scan_buttons.append(&scan_folder);
    let progress = gtk::ProgressBar::new();
    progress.set_show_text(true);
    progress.set_text(Some("idle"));
    let findings_list = gtk::ListBox::new();
    findings_list.set_selection_mode(gtk::SelectionMode::None);
    let findings_scroll = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .child(&findings_list)
        .build();
    scan_page.append(&scan_buttons);
    scan_page.append(&progress);
    scan_page.append(&findings_scroll);

    let quarantine_page = gtk::Box::new(Orientation::Vertical, 12);
    quarantine_page.set_margin_top(18);
    quarantine_page.set_margin_bottom(18);
    quarantine_page.set_margin_start(18);
    quarantine_page.set_margin_end(18);
    let quarantine_refresh = gtk::Button::with_label("Refresh");
    let quarantine_label = gtk::Label::new(Some("no data"));
    quarantine_label.set_xalign(0.0);
    quarantine_label.set_selectable(true);
    quarantine_label.set_wrap(true);
    quarantine_page.append(&quarantine_refresh);
    quarantine_page.append(&quarantine_label);

    let net_page = gtk::Box::new(Orientation::Vertical, 12);
    net_page.set_margin_top(18);
    net_page.set_margin_bottom(18);
    net_page.set_margin_start(18);
    net_page.set_margin_end(18);
    let net_buttons = gtk::Box::new(Orientation::Horizontal, 8);
    let net_refresh = gtk::Button::with_label("Refresh status");
    net_buttons.append(&net_refresh);
    let audit_entry = gtk::Entry::new();
    audit_entry.set_placeholder_text(Some("IP, CIDR or domain to audit"));
    let audit_button = gtk::Button::with_label("Audit");
    net_buttons.append(&audit_entry);
    net_buttons.append(&audit_button);
    let net_label = gtk::Label::new(Some("no data"));
    net_label.set_xalign(0.0);
    net_label.set_selectable(true);
    net_label.set_wrap(true);
    net_page.append(&net_buttons);
    net_page.append(&net_label);

    stack.add_titled(&status_page, Some("status"), "Status");
    stack.add_titled(&scan_page, Some("scan"), "Scan");
    stack.add_titled(&quarantine_page, Some("quarantine"), "Quarantine");
    stack.add_titled(&net_page, Some("network"), "Network");
    window.set_child(Some(&stack));

    // ------------------------------------------------------ worker channels
    let (ui_tx, ui_rx) = async_channel::unbounded::<Msg>();
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Cmd>();
    spawn_worker(ui_tx, cmd_rx);

    // ------------------------------------------------------------ callbacks
    {
        let cmd_tx = cmd_tx.clone();
        status_refresh.connect_clicked(move |_| {
            let _ = cmd_tx.send(Cmd::RefreshStatus);
        });
    }
    {
        let cmd_tx = cmd_tx.clone();
        let window = window.clone();
        scan_file.connect_clicked(move |_| {
            let dialog = gtk::FileDialog::builder()
                .title("Select a file to scan")
                .build();
            let cmd_tx = cmd_tx.clone();
            dialog.open(Some(&window), gtk::gio::Cancellable::NONE, move |result| {
                if let Ok(file) = result {
                    if let Some(path) = file.path() {
                        let _ = cmd_tx.send(Cmd::Scan(path));
                    }
                }
            });
        });
    }
    {
        let cmd_tx = cmd_tx.clone();
        let window = window.clone();
        scan_folder.connect_clicked(move |_| {
            let dialog = gtk::FileDialog::builder()
                .title("Select a folder to scan")
                .build();
            let cmd_tx = cmd_tx.clone();
            dialog.select_folder(Some(&window), gtk::gio::Cancellable::NONE, move |result| {
                if let Ok(folder) = result {
                    if let Some(path) = folder.path() {
                        let _ = cmd_tx.send(Cmd::Scan(path));
                    }
                }
            });
        });
    }
    {
        let cmd_tx = cmd_tx.clone();
        quarantine_refresh.connect_clicked(move |_| {
            let _ = cmd_tx.send(Cmd::RefreshQuarantine);
        });
    }
    {
        let cmd_tx = cmd_tx.clone();
        net_refresh.connect_clicked(move |_| {
            let _ = cmd_tx.send(Cmd::NetStatus);
        });
    }
    {
        let cmd_tx = cmd_tx.clone();
        let audit_entry = audit_entry.clone();
        let send = move || {
            let target = audit_entry.text().to_string();
            if !target.trim().is_empty() {
                let _ = cmd_tx.send(Cmd::NetAudit(target.trim().to_string()));
            }
        };
        audit_button.connect_clicked(move |_| send());
    }
    {
        let cmd_tx = cmd_tx.clone();
        let audit_entry = audit_entry.clone();
        audit_entry.connect_activate(move |_| {
            let target = audit_entry.text().to_string();
            if !target.trim().is_empty() {
                let _ = cmd_tx.send(Cmd::NetAudit(target.trim().to_string()));
            }
        });
    }

    // -------------------------------------------------- initial fetch + UI loop
    let _ = cmd_tx.send(Cmd::RefreshStatus);
    let _ = cmd_tx.send(Cmd::RefreshQuarantine);
    let _ = cmd_tx.send(Cmd::NetStatus);

    {
        let status_label = status_label.clone();
        let progress = progress.clone();
        let findings_list = findings_list.clone();
        let quarantine_label = quarantine_label.clone();
        let net_label = net_label.clone();
        glib::MainContext::default().spawn_local(async move {
            while let Ok(msg) = ui_rx.recv().await {
                match msg {
                    Msg::Daemon(value) => {
                        let text = serde_json::to_string_pretty(&value)
                            .unwrap_or_else(|_| "invalid status".into());
                        status_label.set_text(&text);
                    }
                    Msg::ScanStarted(target) => {
                        progress.set_fraction(0.0);
                        progress.set_text(Some(&format!("scanning {target}")));
                        while let Some(row) = findings_list.first_child() {
                            findings_list.remove(&row);
                        }
                    }
                    Msg::ScanProgress { files, bytes, path } => {
                        progress.set_text(Some(&format!(
                            "{files} files, {} — {path}",
                            zs_core::util::human_bytes(bytes)
                        )));
                    }
                    Msg::Finding(finding) => {
                        let line = format!(
                            "[{}] score {} — {}",
                            finding["severity"].as_str().unwrap_or("?").to_uppercase(),
                            finding["score"].as_u64().unwrap_or(0),
                            finding["path"].as_str().unwrap_or("?")
                        );
                        let label = gtk::Label::new(Some(&line));
                        label.set_xalign(0.0);
                        label.set_selectable(true);
                        let row = gtk::ListBoxRow::new();
                        row.set_child(Some(&label));
                        findings_list.append(&row);
                    }
                    Msg::ScanFinished(report) => {
                        progress.set_fraction(1.0);
                        progress.set_text(Some(&format!(
                            "done: {} files, verdict {}",
                            report["files_scanned"].as_u64().unwrap_or(0),
                            report["verdict"].as_str().unwrap_or("?")
                        )));
                    }
                    Msg::Quarantine(entries) => {
                        if entries.is_empty() {
                            quarantine_label.set_text("quarantine is empty");
                        } else {
                            let mut text = String::new();
                            for e in entries {
                                text.push_str(&format!(
                                    "#{} {} -> {}\n",
                                    e["id"].as_i64().unwrap_or(0),
                                    e["file_name"].as_str().unwrap_or("?"),
                                    e["original_path"].as_str().unwrap_or("?")
                                ));
                            }
                            quarantine_label.set_text(&text);
                        }
                    }
                    Msg::NetStatus(value) => {
                        net_label
                            .set_text(&serde_json::to_string_pretty(&value).unwrap_or_default());
                    }
                    Msg::NetAudit(results) => {
                        let mut text = String::new();
                        for r in results {
                            text.push_str(&format!(
                                "{} → {} {}\n",
                                r["target"].as_str().unwrap_or("?"),
                                r["decision"].as_str().unwrap_or("?").to_uppercase(),
                                r["rule"].as_str().unwrap_or("")
                            ));
                        }
                        net_label.set_text(&text);
                    }
                    Msg::Error(message) => {
                        status_label.set_text(&format!("error: {message}"));
                    }
                }
            }
        });
    }

    window.present();
}

fn spawn_worker(
    ui_tx: async_channel::Sender<Msg>,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
) {
    let socket = Paths::resolve().socket_path();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = ui_tx.send_blocking(Msg::Error(format!("runtime: {e}")));
                return;
            }
        };
        rt.block_on(async move {
            let mut client: Option<zs_ipc::Client> = None;
            while let Some(cmd) = cmd_rx.recv().await {
                if client.is_none() {
                    match zs_ipc::Client::connect(&socket).await {
                        Ok(c) => client = Some(c),
                        Err(e) => {
                            let _ = ui_tx
                                .send(Msg::Error(format!(
                                    "daemon not reachable ({e}). Start it with: zeroshieldd"
                                )))
                                .await;
                            continue;
                        }
                    }
                }
                let c = client.as_mut().expect("client checked above");
                let result: Result<(), zs_core::error::ZsError> = async {
                    match cmd {
                        Cmd::RefreshStatus => {
                            let resp = c
                                .call_simple(methods::STATUS, serde_json::json!({}))
                                .await?;
                            let _ = ui_tx.send(Msg::Daemon(resp.into_result()?)).await;
                        }
                        Cmd::RefreshQuarantine => {
                            let resp = c
                                .call_simple(methods::QUARANTINE_LIST, serde_json::json!({}))
                                .await?;
                            let value = resp.into_result()?;
                            let entries = value["entries"].as_array().cloned().unwrap_or_default();
                            let _ = ui_tx.send(Msg::Quarantine(entries)).await;
                        }
                        Cmd::NetStatus => {
                            let resp = c
                                .call_simple(methods::NET_STATUS, serde_json::json!({}))
                                .await?;
                            let _ = ui_tx.send(Msg::NetStatus(resp.into_result()?)).await;
                        }
                        Cmd::NetAudit(target) => {
                            let resp = c
                                .call_simple(
                                    methods::NET_AUDIT,
                                    serde_json::json!({ "targets": [target] }),
                                )
                                .await?;
                            let value = resp.into_result()?;
                            let results = value["results"].as_array().cloned().unwrap_or_default();
                            let _ = ui_tx.send(Msg::NetAudit(results)).await;
                        }
                        Cmd::Scan(path) => {
                            let tx = ui_tx.clone();
                            let target = path.display().to_string();
                            let _ = tx.send(Msg::ScanStarted(target.clone())).await;
                            let mut on_event = move |event: Event| match event {
                                Event::ScanProgress {
                                    files_scanned,
                                    bytes_scanned,
                                    path,
                                    ..
                                } => {
                                    let _ = tx.send_blocking(Msg::ScanProgress {
                                        files: files_scanned,
                                        bytes: bytes_scanned,
                                        path,
                                    });
                                }
                                Event::ScanFinding { finding, .. } => {
                                    if let Ok(value) = serde_json::to_value(&finding) {
                                        let _ = tx.send_blocking(Msg::Finding(value));
                                    }
                                }
                                _ => {}
                            };
                            let resp = c
                                .call(
                                    methods::SCAN_RUN,
                                    serde_json::json!({ "target": target }),
                                    None,
                                    &mut on_event,
                                )
                                .await?;
                            let _ = ui_tx.send(Msg::ScanFinished(resp.into_result()?)).await;
                        }
                    }
                    Ok(())
                }
                .await;

                if let Err(e) = result {
                    let _ = ui_tx.send(Msg::Error(e.to_string())).await;
                    // Force a reconnect attempt on the next command.
                    client = None;
                }
            }
        });
    });
}

# Roadmap

Status em 2026-10 (v0.1.0 alpha). Cada marco lista o que já existe e o que
falta.

## M0 — Fundação ✅

- [x] Workspace Cargo com crates separados
- [x] Config TOML com defaults e validação
- [x] Resolução de caminhos (XDG, root, `ZS_*`)
- [x] Modelo de dados (findings, eventos, severidades, vereditos)
- [x] Storage SQLite com schema versionado
- [x] Contrato de módulo (`Module`)

## M1 — Daemon + IPC ✅

- [x] Socket Unix com permissões restritas e limpeza de socket órfão
- [x] Protocolo JSON por linha (request/response/event)
- [x] Broadcast de eventos + `watch.start` com stream contínuo
- [x] Dispatch de métodos (status, scan, proc, quarentena, rules, net)
- [x] Logging (texto/JSON) e shutdown gracioso (SIGTERM/SIGINT)
- [ ] Autorização por polkit para clientes não-root (M9)
- [ ] Autenticação por peer-credentials (SO_PEERCRED)

## M2 — Scanner de arquivos ✅

- [x] md5/sha1/sha256 com cache por mtime+tamanho
- [x] Banco de assinaturas (import ClamAV `.hdb`, CSV, hashes soltos)
- [x] Motor de regras de conteúdo TOML (texto/hex/partes, ALL/ANY)
- [x] Heurísticas ELF (segmentos RWX, entropia, marcadores de mineração)
- [x] Pipeline com exclusões, limites de tamanho e progresso
- [x] Quarentena modo `000` + listar/restaurar/purgar
- [x] EICAR detectado por hash, regra e builtin (conteúdo montado em runtime)
- [ ] Cache de "arquivos limpos" por versão de assinatura (M7)
- [ ] Descompactação (zip/tar) para escanear conteúdo interno

## M3 — Monitor de processos ✅ (polling)

- [x] Leitura de `/proc` (stat/status/cmdline/exe) por processo
- [x] Score heurístico com motivos explicáveis
- [x] Watcher por polling com alerta ≥ `alert_score`
- [x] Supressão de falsos positivos sistêmicos (comm truncado, shells,
      interpretadores)
- [ ] Verificação de assinatura de ELF em memória/executável
- [ ] Backend eBPF (aya) atrás de feature flag — M9

## M4 — IPS embutido ✅

- [x] Ingestão de feeds de ameaças (IP/CIDR/domínio) com cache TTL
- [x] Lógica block/allow pura (allowlist vence, sufixo de domínio)
- [x] Geração de ruleset nftables isolado (`inet zeroshield`)
- [x] Modo audit e modo block com fail-safe (root + `--yes`)
- [x] Fragmentos DNS para dnsmasq/Unbound
- [x] `net audit` explica a decisão por alvo
- [ ] Validação de aplicação real em VM/contêiner privilegiado
- [ ] Proteção contra bypass por troca de DNS do cliente
- [ ] Geolocalização/reputação por ASN (opcional)

## M5 — GUI GTK4 ✅ (código) / pendente de validação

- [x] Cliente libadwaita com visão geral, scan, quarentena, processos,
      rede e eventos
- [x] Código-fonte escrito e revisado
- [ ] Compilar/validar em máquina com `libgtk-4-dev`/`libadwaita-1-dev`
      (a CI tem job dedicado)
- [ ] Integração com polkit para operar sem rodar como root

## M6 — Empacotamento e CI ✅

- [x] `nfpm.yaml` (deb/rpm) + `nfpm-gui.yaml`
- [x] `PKGBUILD` Arch + script de instalação
- [x] Unidades systemd (daemon, scan diário + timer) e tmpfiles
- [x] `packaging/config.toml` comentado (`config|noreplace`)
- [x] Ícone e `.desktop`
- [x] CI: fmt, clippy `-D warnings`, testes no Debian (trixie) e Arch,
      build da GUI com GTK4, testes do SDK Python
- [ ] Repositório APT/AUR oficiais
- [ ] `man` pages

## M7 — Tempo real

- [ ] inotify/fanotify em diretórios selecionados (`zeroshield watch`)
- [ ] Cache persistente de arquivos limpos por versão de assinatura
- [ ] Gatilho de scan em montagem de USB (`udev`/udisks)

## M8 — TUI e relatórios

- [ ] TUI (ratatui) para uso em servidores
- [ ] Relatórios `--format json|csv|html`
- [ ] Exportação de métricas (Prometheus/journald)

## M9 — Hardening e v1.0

- [ ] polkit + dbus para CLI/GUI sem privilégio
- [ ] Backend eBPF real (processos em tempo real, sem polling)
- [ ] Assinatura de feeds (GPG) e atualização incremental
- [ ] Fuzzing do parser de regras e do protocolo IPC
- [ ] Auditoria de segurança externa
- [ ] v1.0

## Princípios permanentes

1. **Fail-safe**: nada bloqueia por padrão; o IPS exige opt-in em dois passos.
2. **Explicabilidade**: toda detecção carrega score + motivo.
3. **Sem dependências pesadas no core**: ClamAV/YARA são serviços externos
   opcionais, nunca linkados.
4. **Compatibilidade Debian + Arch**: CI nos dois ambientes.

# Roadmap — ZeroShield

Status em 2026-10 (v0.1.0 alpha). Cada marco lista o que já existe e o que
falta. O [mega teste](#mega-teste-validação-e2e--pendente) fecha as validações
que exigem ambiente real (root, nftables, USB, desktop, feeds assinados).

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
- [x] Autenticação por peer-credentials (SO_PEERCRED)
- [x] Autorização por polkit para clientes não-root (M9-C)

## M2 — Scanner de arquivos ✅

- [x] md5/sha1/sha256 com cache por mtime+tamanho
- [x] Banco de assinaturas (import ClamAV `.hdb`, CSV, hashes soltos)
- [x] Motor de regras de conteúdo TOML (texto/hex/partes, ALL/ANY)
- [x] Heurísticas ELF (segmentos RWX, entropia, marcadores de mineração)
- [x] Pipeline com exclusões, limites de tamanho e progresso
- [x] Quarentena modo `000` + listar/restaurar/purgar
- [x] EICAR detectado por hash, regra e builtin (conteúdo montado em runtime)
- [ ] Descompactação (zip/tar) para escanear conteúdo interno

## M3 — Monitor de processos ✅ (polling)

- [x] Leitura de `/proc` (stat/status/cmdline/exe) por processo
- [x] Score heurístico com motivos explicáveis
- [x] Watcher por polling com alerta ≥ `alert_score`
- [x] Supressão de falsos positivos sistêmicos (comm truncado, shells,
      interpretadores)
- [ ] Verificação de assinatura de ELF em memória/executável
- [ ] Backend eBPF (aya) atrás de feature flag — M9-D

## M4 — IPS embutido ✅

- [x] Ingestão de feeds de ameaças (IP/CIDR/domínio) com cache TTL
- [x] Lógica block/allow pura (allowlist vence, sufixo de domínio)
- [x] Geração de ruleset nftables isolado (`inet zeroshield`)
- [x] Modo audit e modo block com fail-safe (root + `--yes`)
- [x] Fragmentos DNS para dnsmasq/Unbound
- [x] `net audit` explica a decisão por alvo
- [ ] Validação de aplicação real em VM/contêiner privilegiado (mega teste)
- [ ] Proteção contra bypass por troca de DNS do cliente
- [ ] Geolocalização/reputação por ASN (opcional)

## M5 — GUI GTK4 ✅ (código) / pendente de validação

- [x] Cliente libadwaita com visão geral, scan, quarentena, processos,
      rede e eventos
- [x] Código-fonte escrito e revisado; CI compila com GTK4
- [ ] Compilar/validar em máquina com `libgtk-4-dev`/`libadwaita-1-dev`
      (mega teste)
- [x] Integração com polkit para operar sem rodar como root (via daemon,
      M9-C: `polkit_allow_interaction = true` mostra o prompt no desktop)

## M6 — Empacotamento e CI ✅

- [x] `nfpm.yaml` (deb/rpm) + `nfpm-gui.yaml`
- [x] `PKGBUILD` Arch + script de instalação
- [x] Unidades systemd (daemon, scan diário + timer) e tmpfiles
- [x] Política polkit instalada pelos pacotes (`org.zeroshield.read|manage`)
- [x] `packaging/config.toml` comentado (`config|noreplace`)
- [x] Ícone e `.desktop`
- [x] CI: fmt, clippy `-D warnings`, testes no Debian (trixie) e Arch,
      build da GUI com GTK4, testes do SDK Python
- [ ] Repositório APT/AUR oficiais
- [ ] `man` pages

## M7 — Tempo real ✅ (código) / pendente de validação

- [x] inotify em diretórios selecionados (`zeroshield watch`), com debounce,
      subdiretórios recursivos, rebase em renomeação de diretórios e
      relatório de overflow
- [x] Sessões no daemon (`watch.fs.start|stop|list`), auto-start por
      configuração e modo local sem daemon
- [x] Cache persistente de arquivos limpos por versão de assinatura
      (`sig+rules+opções`), invalidado por import de assinaturas ou edição
      de regras
- [x] Gatilho de scan em montagem de USB: o daemon observa `/proc/mounts`
      sob raízes configuráveis e escaneia montagens novas
      (substitui `udev`/udisks por portabilidade Debian+Arch)
- [ ] Validação em máquina com USB real / montagem FUSE (mega teste)
- [ ] fanotify (precisa de `CAP_SYS_ADMIN`; inotify cobre o caso comum)

## M8 — TUI e relatórios ✅ (código) / pendente de validação

- [x] TUI (ratatui) para servidores: abas Overview/Events/Findings/Quarantine/
      Processes/Net, follow ao vivo (~3 s + eventos via `watch.start`),
      detalhes por linha, scan e restore/purge de quarentena na própria TUI,
      tela de espera com reconexão automática quando o daemon está fora
- [x] Relatórios `--format json|csv|html` (`zeroshield report`; CSV por
      `--section findings|scans|events|quarantine`; HTML autocontido, sem JS),
      via daemon (`report.get`) ou modo local
- [x] Exportação de métricas Prometheus/journald (`zeroshield metrics`;
      `zeroshield-metrics.timer` grava `/var/lib/zeroshield/metrics.prom`
      para o textfile collector do node_exporter)
- [ ] Validação de UX da TUI em terminal real e uso prolongado em servidor
      (mega teste)

## M9 — Hardening e v1.0 (em andamento)

Ordem decidida: **A** robustez/fuzzing ✅ → **B** feeds GPG + incremental ✅ →
**C** polkit + peer-credentials ✅ → **D** eBPF → **E** v1.0. Auditoria de
segurança externa após o M9-A (ainda pendente).

- [x] **M9-A** Robustez: limite de frame IPC (1 MiB) e requests em voo (64),
      caps de feeds/regras/assinaturas, correção de overflow no parser ELF,
      mini-fuzzers determinísticos em todo PR + alvos `cargo-fuzz` no job
      semanal
- [x] **M9-B** Assinatura de feeds (GPG) e atualização incremental (`gpgv` +
      keyring próprio, `ETag`/`If-Modified-Since` com `304`, fail-closed:
      assinatura inválida mantém as regras anteriores)
- [x] **M9-C** polkit + peer-credentials para CLI/GUI sem privilégio
      (autorização por `SO_PEERCRED` + polkit via helper `pkcheck`, sem
      dependência de D-Bus no build; ações `org.zeroshield.read|manage`,
      fail-closed; socket `0660` por padrão, `0666` opt-in)
- [ ] **M9-D** Backend eBPF real (processos em tempo real, sem polling)
- [ ] **M9-E** v1.0 (congelar escopo, revisão final da documentação)
- [ ] Auditoria de segurança externa

## Mega teste (validação E2E — pendente)

### Premissa

O desenvolvimento e a CI cobrem unidade, integração e regressão, mas alguns
recursos só podem ser validados em **ambiente real com privilégio** — itens
que o sandbox de desenvolvimento não reproduz (sem root, sem `nft`, sem USB,
sem display, sem feed assinado de terceiros). O mega teste é a passada única
de validação ponta a ponta que fecha esses itens antes do M9-D/v1.0.

Premissas:

1. **Ambiente**: VM ou máquina real com **root**, instalando os pacotes de
   verdade (`nfpm` deb/rpm e `PKGBUILD`) em **Debian (trixie) e Arch**,
   com systemd e acesso à internet (feeds).
2. **Nada de mocks** para os itens marcados como "pendente de validação":
   nftables real, USB real, polkit real com agente, feed assinado real.
3. **Evidência por item**: comando executado, saída relevante e logs do
   daemon; falha vira issue/commit, não silêncio.
4. **Fail-safe em primeiro lugar**: qualquer item que exija bloquear tráfego
   começa em audit/dry-run e só depois em mode block.

### Escopo

- **Instalação**: pacote deb/rpm + PKGBUILD; `config|noreplace` em upgrade;
  `/usr/share/polkit-1/actions/org.zeroshield.policy` presente;
  `/run/zeroshield` 0755 e socket 0660; units e tmpfiles aplicados.
- **Daemon/IPC**: start/stop/restart via systemd, shutdown gracioso, socket
  órfão removido, eventos no journal.
- **Scanner (M2)**: EICAR pelos três caminhos (hash/regra/builtin);
  quarentena `000`; restore/purge; caches de hash e de arquivos limpos.
- **Procmon (M3)**: processo suspeito simulado (binário em `/tmp`, executável
  deletado, memfd) gera alerta com score e motivo.
- **IPS (M4)**: feeds reais; `net apply --yes` aplica a tabela
  `inet zeroshield` (inspecionar com `nft list`); auditoria explica decisões;
  sinkhole dnsmasq/unbound testado com resolução real; allowlist vence.
- **GUI (M5)**: rodar em desktop real, fluxos principais; prompt polkit do
  desktop com `polkit_allow_interaction = true`.
- **Watch/automount (M7)**: sessão inotify com quarentena automática; USB
  real montado dispara scan e aparece nos eventos.
- **TUI/relatórios (M8)**: uso prolongado em terminal real, reconexão com o
  daemon fora; `report` json/csv/html; `metrics.prom` no node_exporter.
- **M9-A**: sanidade dos limites (frame > 1 MiB é rejeitado com erro claro);
  job semanal de fuzzing verde.
- **M9-B**: feed assinado de terceiros (ex.: abuse.ch + keyring público) com
  `feed_signature_required = true`; segunda execução → `not modified` (304);
  assinatura adulterada mantém o cache; `--force` re-verifica.
- **M9-C**: cliente não-root com a política instalada — leitura silenciosa em
  sessão ativa, `auth_admin_keep` (prompt) para `manage` via agente do
  desktop e via `pkttyagent` no CLI; `client_uids`/`client_gids` concedem
  acesso sem polkit; sem polkit → negação fail-closed com log da decisão.
- **Regressão**: `cargo test` (+ `ZS_REQUIRE_GPG=1`) nas duas distros e
  testes do SDK Python.

### Critério de aceite

Todos os itens do escopo executados com evidência anexada; nenhum panic ou
negação indevida; desvios conhecidos documentados (ex.: bypass por troca de
DNS do cliente, ainda aberto no M4).

## Princípios permanentes

1. **Fail-safe**: nada bloqueia por padrão; o IPS exige opt-in em dois passos.
2. **Explicabilidade**: toda detecção carrega score + motivo.
3. **Sem dependências pesadas no core**: ClamAV/YARA são serviços externos
   opcionais, nunca linkados.
4. **Compatibilidade Debian + Arch**: CI nos dois ambientes.

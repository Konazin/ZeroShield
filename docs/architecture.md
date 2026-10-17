# Arquitetura

Este documento descreve como as peças do ZeroShield se encaixam: os crates,
o protocolo IPC, o fluxo de uma varredura, o modelo de processos e o modelo
de segurança.

## Visão geral

```
+----------------+    +----------------+    +-------------------+
| zeroshield     |    | zeroshield-gui |    | zeroshield-sdk    |
| (CLI Rust)     |    | (GTK4)         |    | (Python)          |
+-------+--------+    +-------+--------+    +---------+---------+
        |                     |                       |
        +----------+----------+-----------+-----------+
                   v                      v
          socket Unix (newline JSON)  modo local (CLI sem daemon)
                   v
        +------------------------------+
        | zeroshieldd (root)           |
        |   zs-ipc:  dispatch JSON-RPC |
        |   zs-scan: pipeline de scan  |
        |   zs-watch: inotify/mounts   |
        |   zs-proc: watcher /proc     |
        |   zs-net:  feeds/nft/DNS     |
        +--------------+---------------+
                       v
              /var/lib/zeroshield/zeroshield.db (SQLite)
```

O daemon é a única peça privilegiada. CLI, GUI e SDK são **clientes puros**;
a CLI ainda sabe operar em modo local (in-process) para uso sem systemd/em
contêiner, mas todas as decisões e o estado vivem no mesmo código de crate.

## Crates

| Crate       | Papel                                                                 |
| ----------- | --------------------------------------------------------------------- |
| `zs-core`   | Config TOML, resolução de caminhos (XDG/root), modelo de dados, eventos, storage SQLite, contrato de módulo |
| `zs-ipc`    | Protocolo (frames JSON), servidor Unix com broadcast de eventos, cliente |
| `zs-scan`   | Hashes (md5/sha1/sha256), motor de regras de conteúdo, heurísticas ELF (goblin), assinaturas, quarentena, pipeline do scanner |
| `zs-watch`  | Tempo real: watcher inotify (recursivo, debounce) e observador de `/proc/mounts` para mídia removível |
| `zs-proc`   | Leitura de `/proc`, heurísticas de pontuação de processos, watcher por polling |
| `zs-net`    | Parsing de feeds, lógica block/allow (IP/CIDR/domínio), geração de ruleset nftables, fragmentos DNS (dnsmasq/Unbound), NetGuard |
| `zs-report` | Coleta e renderização de relatórios (JSON/CSV/HTML) e catálogo/render de métricas (Prometheus/journald) |
| `zs-cli`    | Comandos, renderização, shell interativo (`zeroshield`)               |
| `zs-tui`    | Cliente TUI (ratatui) do daemon: abas, follow ao vivo, ações           |
| `zs-daemon` | Bootstrap, logging, dispatch IPC, loop do watcher (`zeroshieldd`)      |
| `zs-gui`    | Cliente GTK4/libadwaita (`zeroshield-gui`)                             |

Todos os módulos implementam o trait `Module` (`zs-core::module`), que expõe
`name`, `description`, `capabilities` e um `status()` usado por
`zeroshield modules` e pelo daemon.

## IPC

O transporte é um socket Unix (padrão `/run/zeroshield/zeroshieldd.sock`,
`0660` por padrão — ver “Autorização de clientes”; em execução não-root,
`$XDG_RUNTIME_DIR/zeroshield/…`). Cada frame é uma linha JSON:

```json
{"id": 1, "method": "status", "params": {}}
{"id": 1, "ok": true,  "result": { ... }}
{"id": 1, "ok": false, "error": "mensagem"}
{"event": {"type": "scan_finding", "scan_id": "...", "finding": { ... }}}
```

- **request/response** casam por `id`;
- **event** frames podem chegar intercalados a qualquer momento (o cliente
  ignora eventos enquanto espera a resposta, ou assiste o stream via
  `watch.start`);
- `scan.run` transmite `scan_started`, `scan_progress`, `scan_finding` e
  `scan_finished` **na conexão do solicitante** e replica os eventos
  persistentes (sem progresso) no **broadcast** do daemon, para que
  `events --follow`/`proc watch` vejam tudo.

Métodos: `status`, `modules`, `scan.run`, `proc.list`, `proc.audit`,
`quarantine.list|restore|purge`, `sigs.import`, `rules.list`,
`events.list`, `findings.list`, `report.get`, `metrics.get`,
`net.status`, `net.audit`, `net.feeds.update`, `net.apply`, `net.dns`,
`watch.start`, `watch.fs.start|stop|list`, `daemon.shutdown`.

## Autorização de clientes (M9-C)

A identidade do cliente vem do kernel: `SO_PEERCRED` na conexão aceita
(uid/gid/pid do processo do outro lado), nunca de dados enviados pelo
cliente. A política é fail-closed:

1. root e o próprio usuário do daemon: confiados (preserva o comportamento
   anterior);
2. `daemon.client_uids` / `daemon.client_gids`: confiados — o gid cobre o
   grupo primário vindo do kernel **e** os suplementares lidos de
   `/proc/<pid>/status`;
3. demais usuários: polkit por requisição, com
   `org.zeroshield.read` para métodos de leitura e
   `org.zeroshield.manage` para os que mudam estado (quarentena,
   assinaturas, rede, shutdown); método novo sem classificação cai em
   `manage`;
4. sem polkit, sem credenciais de kernel ou com processo cliente não
   verificável: nega.

O polkit é consultado através de um helper compatível com `pkcheck` (mesma
filosofia de `gpgv`/`nft`: sem dependência de D-Bus no build), com subject
`unix-process` = `pid,start_time,uid` lido de `/proc` — o uid precisa
bater e o start time imuniza contra reuso de pid. O mesmo check de uid
protege a confiança por grupos suplementares.

Para habilitar clientes não-root: instalar a política
(`packaging/polkit/org.zeroshield.policy`, instalada pelos pacotes) e usar
`daemon.socket_mode = "0666"` — o padrão `0660` só permite o dono. A
política padrão libera leitura para a sessão ativa e pede administrador
para mudanças (`auth_admin_keep`). Sem `polkit_allow_interaction` (padrão)
as checagens nunca bloqueiam esperando input: pedem autenticação e negam.

Depuração: o daemon loga cada negação com uid/gid/pid e motivo. Mensagens
típicas: “polkit is disabled” (adicione o uid a `client_uids` ou ligue
polkit), “requires authentication” (sessão sem agente/autenticação),
“cannot verify client process” (processo cliente morreu antes do check).

## Fluxo de uma varredura

1. O cliente envia `scan.run` com `target` + opções (recursivo, quarentena,
   score mínimo, tamanho máximo, symlinks).
2. O daemon monta as opções, gera um `scan_id`, emite `scan_started` e roda o
   pipeline em `spawn_blocking` para não travar o runtime tokio.
3. O pipeline percorre o alvo (sem seguir symlinks por padrão), aplica
   exclusões, e para cada arquivo:
   - respeita `max_file_size` e o cache de hash (mtime + tamanho);
   - consulta o **cache de arquivos limpos** (`clean_cache`): se o arquivo
     já foi escaneado limpo com o mesmo tamanho/mtime e a mesma versão de
     assinaturas/regras, ele é contado como `cached` e não é relido;
   - calcula md5/sha1/sha256 e consulta o banco de assinaturas;
   - com arquivo ≤ `content_scan_max_bytes`, aplica as regras de conteúdo;
   - se for ELF, roda as heurísticas (RWX, entropia, marcadores de mineração);
   - soma os scores; arquivos com score ≥ `min_report_score` viram `Finding`;
   - arquivos com score 0 entram no cache de limpos (chave: caminho);
   - com quarentena ligada, o arquivo malicioso é movido para
     `/var/lib/zeroshield/quarantine` com modo `000`.
4. Cada achado vira evento (`scan_finding`); o resumo final é persistido
   (`scans`) e emitido (`scan_finished`).
5. A resposta HTTP-like é o `ScanReport` completo. A CLI termina com código
   **2** se houver veredito malicioso.

Limiares de veredito: `≥ 70` malicioso, `≥ 40` suspeito (constantes em
`zs-core::model`).

## Monitor de processos

O watcher roda no daemon (loop tokio) com intervalo configurável, lê
`/proc/<pid>/{stat,status,cmdline,exe}` e pontua cada processo **novo**:

- executável deletado (+60), execução via `memfd` (+70), binário em `/tmp`
  ou `/dev/shm` (+30/+45), root executando binário gravável pelo usuário
  (+70), máscara de kernel thread (+85), linhas de comando de shell reverso,
  `nc -e`, pipes de download, LD_PRELOAD (+55), ...
- diferenças "sistêmicas" de nome (`comm` truncado em 15 bytes, shells como
  `sh` → `dash`, interpretadores reescrevendo o título) **não** pontuam.

Processos com score ≥ `procmon.alert_score` geram evento `proc_alert`,
persistido e transmitido no broadcast. O backend atual é polling portátil;
eBPF (aya) está planejado atrás de feature flag no M9 para eventos em tempo
real sem polling.

## Tempo real (zs-watch)

- **Sessões**: `watch.fs.start` cria uma sessão no daemon (inotify, um
  `inotify` fd por sessão, thread dedicada com fd não-bloqueante e poll de
  ~25 ms). `watch.fs.stop` encerra (todas ou só as que cobrem um caminho) e
  `watch.fs.list` mostra as ativas. Com `watch.enabled` no config, o daemon
  inicia sessões no boot.
- **Escaneamento**: eventos `CLOSE_WRITE`/`MOVED_TO` entram numa fila com
  debounce configurável; quando o arquivo "assenta", ele passa pelo mesmo
  pipeline (`scan_named`) com `record: false` (não polui o histórico de
  scans) e quarentena opcional. Diretórios criados/movidos são registrados
  recursivamente; renomeações de diretório são rebaseadas via *move cookie*
  do inotify. Overflow de fila do kernel vira evento `warning`.
- **Armamento**: `watch.fs.start` só responde depois que os watches iniciais
  estão registrados, então um arquivo criado logo após o retorno do comando
  já é visto.
- **Mídia removível**: o daemon observa `/proc/mounts` a cada
  `automount.poll_interval_secs` sob as raízes configuradas (`/media`,
  `/run/media`, `/mnt`) — sem depender de udev/udisks — emite
  `device_mounted` e escaneia a montagem nova com registro normal no
  histórico.
- **Sem daemon**: `zeroshield watch` sem daemon roda o mesmo `FileWatcher`
  no processo da CLI (modo local), com os mesmos eventos no terminal.

## IPS (zs-net)

- **Feeds**: download via `curl` (TLS do sistema) para
  `~/.cache/zeroshield/feeds` (ou cache XDG), parsing de
  IP/CIDR/domínio/comentários, importação para a tabela `net_rules` com
  origem por feed.
- **Atualização incremental**: re-downloads usam requisições condicionais
  (`If-Modified-Since` + `ETag` via `curl -z/--etag-compare/--etag-save`);
  um `304 Not Modified` mantém o cache e pula o parsing.
- **Assinatura (recomendado)**: com `netguard.feed_signature_required = true`
  todo feed novo precisa da assinatura destacada `<url>.asc`, verificada por
  `gpgv` contra `netguard.feed_keyring` (keyring binário, `gpg --export`;
  nada de `~/.gnupg`). Assinatura ausente ou inválida **descarta o download**
  e mantém o cache e as regras anteriores (fail-closed).
- **Decisão**: `Blocklist` puro — allowlist sempre vence, matching por CIDR e
  por sufixo de domínio (`evil.example` cobre `sub.evil.example`).
- **Aplicação**: o ruleset nftables é **sempre gravado em arquivo**
  (`netguard.nft` no diretório de dados) para auditoria; aplicar de verdade
  exige `mode = "block"` + root + `--yes` e usa uma tabela isolada
  (`inet zeroshield`), com `flush` antes de reaplicar.
- **DNS**: fragmentos prontos para incluir no dnsmasq/Unbound
  (`address=/dominio/0.0.0.0`, `local-zone`), instaláveis em
  `/etc/dnsmasq.d` ou `/etc/unbound/unbound.conf.d` apenas por root.
- Tudo **falha em segurança**: sem root ou sem `nft`, o módulo só relata o
  que faria.

## Storage

SQLite (rusqlite com `bundled`), caminho `$ZS_DATA_DIR/zeroshield.db`
(padrão `/var/lib/zeroshield/zeroshield.db`, modo `0700`). Tabelas:

| Tabela        | Conteúdo                                             |
| ------------- | ---------------------------------------------------- |
| `events`      | eventos persistidos (kind, severidade, payload)      |
| `scans`       | resumo de varreduras                                 |
| `findings`    | achados individuais (path, hashes, score, detecções) |
| `file_hashes` | cache de hashes (mtime + tamanho)                    |
| `clean_files` | cache de arquivos limpos (path, tamanho, mtime, versão) |
| `signatures`  | assinaturas de hash importadas/semeadas              |
| `quarantine`  | entradas de quarentena (id, caminho original, modo)  |
| `net_rules`   | regras de rede (ip/cidr/domain + origem)             |
| `meta`        | versão de schema e carimbos                          |

## Relatórios e métricas (zs-report)

O crate `zs-report` não fala IPC: ele recebe dados já coletados e os
transforma. Duas frentes:

- **Relatórios** (`zeroshield report`): `ReportOptions { days, limit }`
  (dias ≤ 3650, limite 1..=10000) alimentam `collect()`, que monta
  `ReportData { generated_at, version, host, summary, scans, findings }` a
  partir do `Storage`. A renderização tem três formatos — JSON, CSV (RFC 4180
  com `--section findings|scans|events|quarantine`) e HTML autocontido (CSS
  inline, sem JavaScript e sem template engine). O daemon expõe a mesma
  coleta como `report.get`, expondo contagens de eventos por severidade;
- **Métricas** (`zeroshield metrics`): `MetricsInput` → `MetricSet` → render
  Prometheus (texto 0.0.4 com `HELP`/`TYPE` uma vez por família e labels
  escapados) ou journald (`k=v` em uma linha). Catálogo `zeroshield_*`:
  `up`, `info`, `uptime_seconds`, `scans_total`, `threats_total`,
  `findings_total`, `quarantine_entries`, `signatures_total`, `rules_total`,
  `clean_cache_entries`, `watch_sessions`, `watched_dirs`, `net_rules`,
  `procmon_processes`, `events_total{severity=...}`.

Via daemon, os valores vêm do estado vivo (`metrics.get` inclui
`scanner.rules()`, sessões de watch, regras nftables e contagem de processos);
em modo local a coleta usa o mesmo `Storage`, mas marca `zeroshield_up 0` para
não mentir sobre o daemon. O `zeroshield-metrics.timer` grava
`/var/lib/zeroshield/metrics.prom` a cada 5 min para o textfile collector do
node_exporter.

## TUI (zs-tui)

`zeroshield tui` é um cliente puro do daemon (sem modo local). O estado
(`App`) é separado da coleta (`data.rs`):

- **Poller**: a cada ~3 s (mínimo de 1 s entre refreshes) coleta `status` +
  `events.list` sempre e, apenas para a aba visível, a seção correspondente
  (`findings.list`, `quarantine.list`, `proc.list`, `net.status`) — abas
  pesadas não custam nada quando fechadas;
- **Streamer**: mantém uma conexão dedicada em `watch.start`; cada evento do
  broadcast incrementa o contador de novidades e acorda o poller
  (debounce), dando follow "instantâneo" sem polling agressivo;
- **Scan**: `s` abre o input; o `scan.run` roda em outra conexão dedicada, o
  que permite consumir os eventos `scan_progress` (que são exclusivos da
  conexão do solicitante) e mostrá-los no rodapé;
- **Ações**: `x`/`X` pedem confirmação e chamam `quarantine.restore|purge`;
  reconexão é automática — sem daemon, a tela de espera aparece e o poller
  continua tentando;
- **Testes**: estado/teclado em testes puros e render com
  `ratatui::TestBackend` (todas as abas, overlays, terminal minúsculo e a
  tela offline), sem exigir TTY.

## Modelo de segurança

- Identidade de cliente via `SO_PEERCRED` (kernel), autorização por
  uid/gid confiados (`daemon.client_uids`/`client_gids`) ou polkit por
  requisição (`org.zeroshield.read`/`org.zeroshield.manage`), fail-closed —
  ver “Autorização de clientes (M9-C)”. Socket `0660` por padrão; clientes
  não-root exigem `daemon.socket_mode` mais permissivo + política polkit.
- Quarentena: diretório `0700`, arquivos `000`; restaurar exige o daemon e
  nunca sobrescreve arquivos existentes.
- O daemon não executa conteúdo escaneado; heurísticas ELF são leitura pura.
- Feeds são baixados somente via HTTPS (`curl --proto '=https'
  --tlsv1.2`).
- Assinaturas de feed são verificadas com `gpgv` e keyring próprio, sem
  estado em `~/.gnupg`; falha de verificação nunca substitui o cache
  (fail-closed).
- Unidades systemd endurecidas (`ProtectSystem=strict`, `NoNewPrivileges`,
  `SystemCallFilter=@system-service`), com `ReadWritePaths` restrito a
  `/var/lib/zeroshield` e `/run/zeroshield`.

## Limites de robustez

Entradas não confiáveis nunca podem fazer o daemon alocar memória sem limite
nem derrubá-lo com um panic. Os limites atuais:

| Limite | Valor | Constante |
|---|---|---|
| Frame IPC | 1 MiB (sem o `\n`) | `zs_ipc::protocol::MAX_FRAME_BYTES` |
| Requests em voo por conexão | 64 | `zs_ipc::protocol::MAX_INFLIGHT_REQUESTS` |
| Arquivo de feed | 64 MiB | `zs_net::feeds::MAX_FEED_BYTES` (+ `curl --max-filesize`) |
| Arquivo de assinatura | 1 MiB | `zs_net::signature::MAX_SIGNATURE_BYTES` (+ `curl --max-filesize`) |
| Entradas por feed | 1.000.000 | `zs_net::feeds::MAX_FEED_ENTRIES` |
| Linha de feed | 8 KiB | `zs_net::feeds::MAX_FEED_LINE_BYTES` |
| Arquivo de regras | 8 MiB | `zs_scan::rules::MAX_RULE_FILE_BYTES` |
| Arquivo de assinaturas | 64 MiB | `zs_scan::signatures::MAX_SIG_IMPORT_BYTES` |
| Linha de assinatura | 4 KiB | `zs_scan::signatures::MAX_SIG_LINE_BYTES` |

Um frame acima do limite recebe resposta de erro e a conexão é fechada;
linhas acima do limite são puladas com `warn`. Os parsers (frame IPC, feeds,
regras, assinaturas, config e heurísticas ELF) são cobertos por mini-fuzzers
determinísticos (`crates/*/tests/mini_fuzz.rs`, em todo PR com Rust stable) e
por alvos `cargo-fuzz` (`fuzz/`, job semanal da CI).

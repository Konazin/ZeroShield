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
| `zs-proc`   | Leitura de `/proc`, heurísticas de pontuação de processos, watcher por polling |
| `zs-net`    | Parsing de feeds, lógica block/allow (IP/CIDR/domínio), geração de ruleset nftables, fragmentos DNS (dnsmasq/Unbound), NetGuard |
| `zs-cli`    | Comandos, renderização, shell interativo (`zeroshield`)               |
| `zs-daemon` | Bootstrap, logging, dispatch IPC, loop do watcher (`zeroshieldd`)      |
| `zs-gui`    | Cliente GTK4/libadwaita (`zeroshield-gui`)                             |

Todos os módulos implementam o trait `Module` (`zs-core::module`), que expõe
`name`, `description`, `capabilities` e um `status()` usado por
`zeroshield modules` e pelo daemon.

## IPC

O transporte é um socket Unix (padrão `/run/zeroshield/zeroshieldd.sock`,
`0660 root:root`; em execução não-root, `$XDG_RUNTIME_DIR/zeroshield/…`).
Cada frame é uma linha JSON:

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
`events.list`, `findings.list`, `net.status`, `net.audit`,
`net.feeds.update`, `net.apply`, `net.dns`, `watch.start`, `daemon.shutdown`.

## Fluxo de uma varredura

1. O cliente envia `scan.run` com `target` + opções (recursivo, quarentena,
   score mínimo, tamanho máximo, symlinks).
2. O daemon monta as opções, gera um `scan_id`, emite `scan_started` e roda o
   pipeline em `spawn_blocking` para não travar o runtime tokio.
3. O pipeline percorre o alvo (sem seguir symlinks por padrão), aplica
   exclusões, e para cada arquivo:
   - respeita `max_file_size` e o cache de hash (mtime + tamanho);
   - calcula md5/sha1/sha256 e consulta o banco de assinaturas;
   - com arquivo ≤ `content_scan_max_bytes`, aplica as regras de conteúdo;
   - se for ELF, roda as heurísticas (RWX, entropia, marcadores de mineração);
   - soma os scores; arquivos com score ≥ `min_report_score` viram `Finding`;
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

## IPS (zs-net)

- **Feeds**: download via `curl` (TLS do sistema) para
  `~/.cache/zeroshield/feeds` (ou cache XDG), parsing de
  IP/CIDR/domínio/comentários, importação para a tabela `net_rules` com
  origem por feed.
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
| `signatures`  | assinaturas de hash importadas/semeadas              |
| `quarantine`  | entradas de quarentena (id, caminho original, modo)  |
| `net_rules`   | regras de rede (ip/cidr/domain + origem)             |
| `meta`        | versão de schema e carimbos                          |

## Modelo de segurança

- Socket `0660 root:root` no modo sistema: só root fala com o daemon hoje;
  polkit/dbus para usuários está no roadmap (M9).
- Quarentena: diretório `0700`, arquivos `000`; restaurar exige o daemon e
  nunca sobrescreve arquivos existentes.
- O daemon não executa conteúdo escaneado; heurísticas ELF são leitura pura.
- Feeds são baixados somente via HTTPS (`curl --proto '=https'
  --tlsv1.2`).
- Unidades systemd endurecidas (`ProtectSystem=strict`, `NoNewPrivileges`,
  `SystemCallFilter=@system-service`), com `ReadWritePaths` restrito a
  `/var/lib/zeroshield` e `/run/zeroshield`.

# ZeroShield

![CI](https://github.com/Konazin/ZeroShield/actions/workflows/ci.yml/badge.svg)
![Licença: MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-blue)

Antivírus open source para Linux, compatível com **Debian** e **Arch**, com:

- **Analisador de arquivos** — assinaturas de hash (MD5/SHA-1/SHA-256),
  regras de conteúdo e heurísticas de ELF (sem linkar ClamAV);
- **Avaliação de processos suspeitos** — monitora `/proc`, pontua processos
  potencialmente maliciosos (binário deletado, execução via `memfd`, máscaras
  de kernel threads, shells reversos, LD_PRELOAD, ...);
- **IPS embutido** — feeds de ameaças (IP/CIDR/domínio), bloqueio de saída via
  nftables e sinkhole de DNS (dnsmasq/Unbound).

O projeto é um **daemon privilegiado + clientes sem privilégio** (CLI e GUI
GTK4) conversando por socket Unix. Nada é bloqueado por padrão: o IPS começa
em modo *audit*.

> Estado: **v0.1.0 (alpha)** — núcleo, CLI, daemon, scanner, monitor de
> processos e IPS funcionais; GUI GTK4 escrita (compila em ambiente com
> GTK4/libadwaita); empacotamento e CI incluídos. Veja o
> [roadmap](docs/roadmap.md).

## Arquitetura

```
zeroshield (CLI)      zeroshield-gui (GTK4)      zeroshield-sdk (Python)
        \                    |                          /
         \___________________|_________________________/
                             v
                socket Unix /run/zeroshield/zeroshieldd.sock
                     (JSON delimitado por \n)
                             |
                    zeroshieldd (daemon, root)
              +--------------+---------------+
              |              |               |
          zs-scan        zs-proc          zs-net
       scanner de      monitor de       IPS: feeds,
       arquivos        processos        nftables, DNS
              |              |               |
              +--------------+---------------+
                             v
                 SQLite (/var/lib/zeroshield)
         scans · findings · hashes · assinaturas · quarentena · eventos
```

Detalhes em [`docs/architecture.md`](docs/architecture.md).

## Compilando

Requisitos: Rust estável (≥ 1.75), `gcc` e `pkg-config`.

```sh
git clone https://github.com/Konazin/ZeroShield.git
cd ZeroShield
cargo build --release
```

Binários em `target/release/`:

| Binário           | Função                                        |
| ----------------- | --------------------------------------------- |
| `zeroshield`      | CLI (scans, quarentena, processos, rede)      |
| `zeroshieldd`     | daemon privilegiado                           |
| `zeroshield-gui`  | cliente GTK4 (requer `libgtk-4-dev`/`libadwaita-1-dev`; `cargo build -p zs-gui`) |

### Debian

```sh
sudo apt install build-essential pkg-config
# opcional para a GUI:
sudo apt install libgtk-4-dev libadwaita-1-dev
```

### Arch

```sh
sudo pacman -S base-devel rust
# opcional para a GUI:
sudo pacman -S gtk4 libadwaita
```

## Instalando o serviço (systemd)

```sh
sudo install -Dm755 target/release/zeroshield  /usr/bin/zeroshield
sudo install -Dm755 target/release/zeroshieldd /usr/bin/zeroshieldd
sudo install -Dm644 packaging/config.toml -t /etc/zeroshield/
sudo install -Dm644 packaging/systemd/zeroshieldd.service \
    packaging/systemd/zeroshield-scan.service \
    packaging/systemd/zeroshield-scan.timer \
    packaging/systemd/zeroshield-metrics.service \
    packaging/systemd/zeroshield-metrics.timer -t /usr/lib/systemd/system/
sudo install -Dm644 packaging/tmpfiles/zeroshield.conf -t /usr/lib/tmpfiles.d/
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/zeroshield.conf
sudo systemctl daemon-reload
sudo systemctl enable --now zeroshieldd
```

Opcional: `sudo systemctl enable --now zeroshield-metrics.timer` grava
`/var/lib/zeroshield/metrics.prom` a cada 5 minutos (formato texto do
Prometheus, pronto para o *textfile collector* do node_exporter).

Pacotes: `packaging/nfpm.yaml` gera `.deb`/`.rpm` com
[nfpm](https://nfpm.goreleaser.com/); `packaging/arch/PKGBUILD` gera o pacote
Arch (`makepkg -si`).

## Uso

```sh
# status do daemon (ou modo local, se o daemon estiver parado)
zeroshield status
zeroshield modules

# escanear
zeroshield scan ~/Downloads
zeroshield scan --quarantine /caminho/suspeito.bin   # quarentena automática
zeroshield scan --min-score 40 /home                 # só achados ≥ 40

# quarentena
zeroshield quarantine list
zeroshield quarantine restore 1
zeroshield quarantine purge 1

# processos suspeitos
zeroshield proc list --min-score 40
zeroshield proc watch                                # ao vivo (stream de eventos)

# tempo real (inotify)
zeroshield watch ~/Downloads                         # acompanha e escaneia ao vivo
zeroshield watch ~/Downloads -q --detach             # sessão no daemon + quarentena
zeroshield watch --list                              # sessões ativas
zeroshield watch --stop                              # encerra as sessões

# IPS (modo audit por padrão)
zeroshield net status
zeroshield net audit 203.0.113.7 malware.example
zeroshield net feeds update
zeroshield net apply            # dry-run: gera o ruleset nftables
sudo zeroshield net apply --yes # aplica de verdade (mode = "block")
zeroshield net dns              # fragmento de sinkhole (dnsmasq/unbound)

# eventos
zeroshield events -n 50
zeroshield events --follow      # stream ao vivo do daemon

# relatórios (json | csv | html)
zeroshield report                                # últimos 7 dias
zeroshield report --days 30 --format csv --section scans
zeroshield report --format html --out /tmp/zeroshield.html

# métricas (Prometheus | journald | json)
zeroshield metrics --format prometheus
zeroshield metrics --format journald
zeroshield metrics --format prometheus --out /var/lib/zeroshield/metrics.prom

# TUI para servidores (somente leitura + ações; requer o daemon)
zeroshield tui

# shell interativo
zeroshield shell
```

O scan retorna **código de saída 2** quando encontra ameaças (como o `grep`),
facilitando o uso em scripts e timers.

A TUI (`zeroshield tui`) segue o daemon ao vivo (~3 s + eventos em tempo real):
`1..6`/`Tab` trocam de aba (Overview, Events, Findings, Quarantine, Processes,
Net), `Enter` abre os detalhes, `s` dispara um scan, `x`/`X` restauram/purgam
uma entrada da quarentena, `p` pausa o follow, `?` mostra a ajuda. Sem o daemon
ela mostra a tela de espera e continua tentando reconectar.

Sem o daemon rodando, a CLI funciona em **modo local** (`--local` força), útil
para escanear máquinas sem systemd ou dentro de contêineres.

## Configuração

Ordem de busca: `$ZS_CONFIG` → `/etc/zeroshield/config.toml` →
`~/.config/zeroshield/config.toml`. Um exemplo comentado está em
[`packaging/config.toml`](packaging/config.toml). Destaques:

```toml
[scanner]
quarantine = false        # quarentena automática no scan
min_report_score = 20     # score mínimo para reportar
clean_cache = true        # reusa veredito de arquivos já escaneados limpos

[watch]
enabled = false           # tempo real via inotify
paths = ["/home", "/tmp"]
quarantine = false
debounce_ms = 800

[automount]
enabled = false           # escaneia mídia removível ao montar
roots = ["/media", "/run/media", "/mnt"]

[procmon]
enabled = true
poll_interval_secs = 5
alert_score = 40          # score mínimo para alertar

[netguard]
enabled = false           # IPS desligado por padrão
mode = "audit"            # "audit" ou "block"
dns_mode = "off"          # "dnsmasq" ou "unbound"
blocklist = ["198.51.100.0/24", "malware.example"]
allowlist = ["trusted.example"]
```

Variáveis de ambiente úteis: `ZS_CONFIG`, `ZS_DATA_DIR`, `ZS_SOCKET`,
`RUST_LOG`.

### Assinaturas e regras

- assinaturas de hash: `zeroshield rules import arquivo.{hdb,csv,txt}` —
  formatos ClamAV `.hdb`, CSV (`sha256,nome,severidade,descrição`) e hashes
  soltos (um por linha, com nome opcional);
- regras de conteúdo: arquivos `.toml` em `/usr/share/zeroshield/rules` e nos
  diretórios de `scanner.rule_dirs`. Veja o formato em
  [`crates/zs-scan/rules/embedded.toml`](crates/zs-scan/rules/embedded.toml).

## Segurança e privacidade

- O daemon roda como **root** (necessário para ler `/proc` de todos e chamar
  `nft`); a CLI/GUI rodam **sem privilégio** e só conversam pelo socket.
- O IPS **nunca** liga sozinho: `enabled = false`, `mode = "audit"` e a
  aplicação real exige root **e** `--yes`.
- Quarentena deixa o arquivo com modo `000` e o restaura/metadata são
  registrados no banco.
- ClamAV/YARA são vistos apenas como **serviços externos** opcionais — nunca
  linkados ao binário.
- Nenhum script é executado no reboot; o IPS gera o ruleset em arquivo e a
  aplicação é explícita.

## SDK Python

O pacote `python/zeroshield_sdk` fala o mesmo protocolo do daemon e é a base
do futuro sistema de plugins/automação:

```python
from zeroshield_sdk import Client

with Client() as zs:          # usa $ZS_SOCKET ou o caminho padrão
    print(zs.status())
    report = zs.scan("/tmp/arquivo")
    print(zs.report(days=30)["summary"])
    print(zs.metrics()["up"])
    for event in zs.watch():
        print(event)
```

Testes: `python3 -m unittest discover -s python/tests`.

## Desenvolvimento

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
python3 -m unittest discover -s python/tests
```

Rodadas de fuzzing cobrem os parsers de entrada não confiável (frame IPC,
feeds, regras, assinaturas, config e heurísticas ELF); exigem toolchain
nightly e `cargo-fuzz`:

```sh
cargo install cargo-fuzz
cd fuzz && cargo fuzz run ipc_frame -- -max_total_time=60
```

Alvos e corpus em [`fuzz/`](fuzz/README.md). Em todo PR, os mesmos parsers
passam por mini-fuzzers determinísticos em `crates/*/tests/mini_fuzz.rs`.

O workspace separa o núcleo em crates (`zs-core`, `zs-ipc`, `zs-scan`,
`zs-watch`, `zs-proc`, `zs-net`, `zs-report`, `zs-cli`, `zs-tui`, `zs-daemon`,
`zs-gui`), com testes unitários em cada um. A CI roda fmt, clippy, testes no
Debian (trixie) e Arch, build da GUI com GTK4 e os testes do SDK Python — veja
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Roadmap

- [x] **M0** Fundação (workspace, config, storage, modelo de evento)
- [x] **M1** Daemon + IPC (socket, JSON, streaming de eventos)
- [x] **M2** Scanner de arquivos (hashes, regras, ELF, quarentena)
- [x] **M3** Monitor de processos (polling de `/proc`; eBPF planejado)
- [x] **M4** IPS (feeds, nftables, DNS; validação real em VM pendente)
- [x] **M5** GUI GTK4 (código pronto; compilação validada só com GTK4)
- [x] **M6** Empacotamento (deb via nfpm, PKGBUILD, systemd, CI)
- [x] **M7** Tempo real (inotify, cache de arquivos limpos, scan de mídia
      removível; validação com USB real pendente)
- [x] **M8** TUI + relatórios (ratatui, json/csv/html, métricas
      Prometheus/journald; validação de UX em terminal real pendente)
- [ ] **M9** Hardening, polkit, eBPF e v1.0

Detalhes em [`docs/roadmap.md`](docs/roadmap.md).

## Licença

MIT — veja [LICENSE](LICENSE).

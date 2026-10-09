# homelab-tiny-tools

Small, single-purpose tools from a self-hosted homelab (Proxmox, WireGuard,
CrowdSec, Traefik/Authelia). Each tool lives in its own folder with a README,
an example systemd unit where it makes sense, and tests.

No frameworks and no agents: copy the one file you need.

## Tools

### CrowdSec

| Tool | Purpose (one line) | Usage | Safety | Status |
|---|---|---|---|---|
| [wg-peer-whitelist](crowdsec/wg-peer-whitelist/) | Keeps WireGuard peers' public endpoint IPs on a CrowdSec whitelist (parser file or `cscli allowlists`) so bouncers never lock your own VPN clients out. | `wg-peer-whitelist --dry-run`, then enable the systemd timer | Dry-run first; never prints keys; refuses empty/foreign files; writes one file, reloads only on change | tested |

### WireGuard

| Tool | What it does | Status |
|---|---|---|
| [wg-peer-whitelist](crowdsec/wg-peer-whitelist/) (lives under `crowdsec/`) | See above. Use it if you run WireGuard behind a CrowdSec firewall bouncer. | tested |

### Proxmox

_Nothing yet._

### Traefik / Authelia

_Nothing yet._

## Install with an AI assistant

Paste this into an AI coding agent (Claude Code or similar) that has shell access to the host
where you want to use a tool. Replace `<TOOL>` with the folder name, e.g. `wg-peer-whitelist`:

````text
I want to use the tool "<TOOL>" from https://github.com/WaldemarFech/homelab-tiny-tools on this
machine. Work carefully and follow these rules:

1. Clone the repository, then READ the tool's README and its whole script before running
   anything. Summarize in a few lines what it reads, what it writes and which commands it runs
   (including as root). If anything is unclear or surprising, tell me.
2. Ask me for the settings that depend on my setup (paths, interface names, how my services are
   reached, which service to reload) - do not guess them and do not use values from examples
   as if they were mine.
3. Never ask for, read, print or store my passwords, keys or tokens. If a step needs one, show
   me the command and let me run it myself. Never print private keys that the tool may touch.
4. Run the tool with `--dry-run` FIRST (and `--print` if available). Show me the exact diff or
   output and explain each change. Do not apply anything yet.
5. Ask for my explicit confirmation before the real run, before installing files into system
   paths (/usr/local/sbin, /etc/...) and before enabling any systemd timer. Show the exact
   commands you will run.
6. After applying, verify (service/timer status, journal, the tool's own check) and report the
   real results. Tell me how to undo it (the tool's Uninstall section).
````

**Status legend:** *tested* = unit tests plus verified against a real setup ·
*experimental* = works on the author's setup, interfaces may change.

## Conventions

- One folder per tool: `<category>/<tool>/`, containing `README.md`, the
  script, `systemd/` examples if relevant, and `tests/`.
- Configuration comes from flags or environment variables. Nothing about
  hosts or IPs is hard-coded.
- Every tool that changes something has a `--dry-run`.
- Example addresses use the documentation ranges (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`).

## License

Apache License 2.0 – see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright 2026 Waldemar Fech. Forks and derivative works must keep the NOTICE file and credit the original author.
(Versions up to and including the previous release were published under MIT.)

## Release status

- **Tested:** unit tests for `wg-peer-whitelist`: 17 passed, 1 skipped (`python -m pytest -q crowdsec/wg-peer-whitelist/tests`, 2026-10-09). Tools marked *tested* above were also run against a real setup.
- **Open:** tools not marked *tested* have no automated tests yet; no CI beyond the `wg-peer-whitelist` suite; only Linux with systemd is exercised.

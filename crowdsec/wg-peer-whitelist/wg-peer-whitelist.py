#!/usr/bin/env python3
"""wg-peer-whitelist: keep WireGuard peer IPs on a CrowdSec whitelist.

Reads the peer list from `wg show all dump`, extracts the peers' public
endpoint IPs (and/or their AllowedIPs), and writes them to a dedicated
CrowdSec whitelist so that CrowdSec bouncers never ban your own VPN clients.

Two backends:
  parser     (default) writes a standalone s02-enrich whitelist parser YAML
             and reloads CrowdSec only when the content changed.
  allowlist  (experimental) syncs a centralized allowlist via
             `cscli allowlists` (CrowdSec >= 1.6.8).

Stdlib only, Python >= 3.8. MIT licensed.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Set

VERSION = "1.0.0"
MANAGED_HEADER = "# Managed by wg-peer-whitelist - manual edits are overwritten.\n"

DEFAULTS = {
    "WGPW_WG_CMD": "wg show all dump",
    "WGPW_SOURCE": "endpoints",
    "WGPW_BACKEND": "parser",
    "WGPW_OUTPUT": "/etc/crowdsec/parsers/s02-enrich/zz-wg-peer-whitelist.yaml",
    "WGPW_PARSER_NAME": "local/wg-peer-whitelist",
    "WGPW_ALLOWLIST": "wireguard-peers",
    "WGPW_RELOAD_CMD": "systemctl reload crowdsec",
    "WGPW_CSCLI": "cscli",
    "WGPW_LOCK_FILE": "/run/lock/wg-peer-whitelist.lock",
}


@dataclass
class Peer:
    interface: str
    endpoint_ip: Optional[str]
    allowed_ips: List[str] = field(default_factory=list)
    latest_handshake: int = 0


def log(msg: str) -> None:
    print(f"wg-peer-whitelist: {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _endpoint_host(endpoint: str) -> Optional[str]:
    """'203.0.113.5:51820' -> '203.0.113.5', '[2001:db8::1]:51820' -> '2001:db8::1'."""
    if not endpoint or endpoint == "(none)":
        return None
    if endpoint.startswith("["):
        host = endpoint[1:].split("]", 1)[0]
    else:
        host = endpoint.rsplit(":", 1)[0]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def parse_dump(text: str) -> List[Peer]:
    """Parse `wg show all dump` (9 tab-separated fields per peer line).

    Interface lines (5 fields, containing the private key) are skipped and
    their content is never stored. A single-interface dump (`wg show wg0 dump`,
    8 fields per peer) is accepted too.
    """
    peers: List[Peer] = []
    for raw in text.splitlines():
        parts = raw.rstrip("\n").split("\t")
        if len(parts) == 9:
            iface, _pub, _psk, endpoint, allowed, handshake = parts[:6]
        elif len(parts) == 8:
            iface = ""
            _pub, _psk, endpoint, allowed, handshake = parts[:5]
        else:
            continue  # interface line or garbage: ignore
        allowed_list = [] if allowed in ("", "(none)") else allowed.split(",")
        try:
            hs = int(handshake)
        except ValueError:
            hs = 0
        peers.append(Peer(iface, _endpoint_host(endpoint), allowed_list, hs))
    return peers


# Ranges that are not routable on the internet. Peers arriving from these are
# typically already covered by CrowdSec's stock private-range whitelist, so by
# default they are skipped. Defined explicitly (instead of ipaddress.is_global)
# so behaviour is predictable across Python versions.
LOCAL_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "::/128", "::1/128", "fc00::/7", "fe80::/10",
)]


def _is_public(net: ipaddress._BaseNetwork) -> bool:
    return not any(net.version == l.version and net.subnet_of(l) for l in LOCAL_NETS)


def collect_entries(
    peers: Iterable[Peer],
    source: str,
    include_private: bool,
    max_handshake_age: int,
    interfaces: Sequence[str],
    now: Optional[int] = None,
) -> Set[ipaddress._BaseNetwork]:
    now = int(time.time()) if now is None else now
    result: Set[ipaddress._BaseNetwork] = set()
    for p in peers:
        if interfaces and p.interface and p.interface not in interfaces:
            continue
        if max_handshake_age > 0 and (p.latest_handshake == 0 or now - p.latest_handshake > max_handshake_age):
            continue
        candidates: List[str] = []
        if source in ("endpoints", "both") and p.endpoint_ip:
            candidates.append(p.endpoint_ip)
        if source in ("allowed-ips", "both"):
            candidates.extend(p.allowed_ips)
        for c in candidates:
            try:
                net = ipaddress.ip_network(c.strip(), strict=False)
            except ValueError:
                continue
            if net.prefixlen == 0:
                continue  # never whitelist 0.0.0.0/0 or ::/0 (full-tunnel peers)
            if not include_private and not _is_public(net):
                continue
            result.add(net)
    return result


def parse_extra(values: Iterable[str]) -> Set[ipaddress._BaseNetwork]:
    out: Set[ipaddress._BaseNetwork] = set()
    for v in values:
        for item in v.replace(",", " ").split():
            net = ipaddress.ip_network(item, strict=False)
            if net.prefixlen == 0:
                raise ValueError(f"refusing to whitelist {item}")
            out.add(net)
    return out


def _sort_key(n: ipaddress._BaseNetwork):
    return (n.version, int(n.network_address), n.prefixlen)


# --------------------------------------------------------------------------- #
# Parser backend
# --------------------------------------------------------------------------- #
def render_parser_yaml(entries: Set[ipaddress._BaseNetwork], name: str, reason: str) -> str:
    hosts = sorted((n for n in entries if n.num_addresses == 1), key=_sort_key)
    nets = sorted((n for n in entries if n.num_addresses > 1), key=_sort_key)
    lines = [
        MANAGED_HEADER.rstrip("\n"),
        f"name: {name}",
        'description: "WireGuard peers - generated by wg-peer-whitelist"',
        "whitelist:",
        f'  reason: "{reason}"',
    ]
    if hosts:
        lines.append("  ip:")
        lines.extend(f'    - "{n.network_address}"' for n in hosts)
    else:
        lines.append("  ip: []")
    if nets:
        lines.append("  cidr:")
        lines.extend(f'    - "{n}"' for n in nets)
    else:
        lines.append("  cidr: []")
    return "\n".join(lines) + "\n"


def atomic_write(path: str, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".wg-peer-whitelist.", dir=directory)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def unified_diff(old: str, new: str, path: str) -> str:
    import difflib

    return "".join(
        difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"{path} (current)", f"{path} (generated)")
    )


# --------------------------------------------------------------------------- #
# Allowlist backend (experimental)
# --------------------------------------------------------------------------- #
def _value_str(n: ipaddress._BaseNetwork) -> str:
    return str(n.network_address) if n.num_addresses == 1 else str(n)


def parse_allowlist_json(text: str) -> Set[str]:
    """Extract item values from `cscli allowlists inspect NAME -o json`."""
    data = json.loads(text or "{}")
    items = data.get("items") if isinstance(data, dict) else data
    values: Set[str] = set()
    for it in items or []:
        if isinstance(it, dict) and it.get("value"):
            values.add(str(it["value"]))
        elif isinstance(it, str):
            values.add(it)
    return values


def sync_allowlist(args, entries: Set[ipaddress._BaseNetwork], run) -> int:
    cscli = shlex.split(args.cscli)
    name = args.allowlist
    lists = run(cscli + ["allowlists", "list", "-o", "json"])
    existing_names = {str(x.get("name")) for x in (json.loads(lists or "[]") or []) if isinstance(x, dict)}
    current: Set[str] = set()
    if name in existing_names:
        current = parse_allowlist_json(run(cscli + ["allowlists", "inspect", name, "-o", "json"]))
    wanted = {_value_str(n) for n in entries}
    to_add, to_remove = sorted(wanted - current), sorted(current - wanted)
    log(f"allowlist '{name}': {len(wanted)} wanted, +{len(to_add)} -{len(to_remove)}")
    for v in to_add:
        print(f"+ {v}")
    for v in to_remove:
        print(f"- {v}")
    if args.dry_run:
        return 0
    if name not in existing_names:
        run(cscli + ["allowlists", "create", name, "-d", "WireGuard peers (wg-peer-whitelist)"])
    if to_add:
        run(cscli + ["allowlists", "add", name, *to_add, "-d", "wireguard peer"])
    if to_remove:
        run(cscli + ["allowlists", "remove", name, *to_remove])
    return 0


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def _run(cmd: Sequence[str]) -> str:
    res = subprocess.run(list(cmd), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.stdout


def build_parser() -> argparse.ArgumentParser:
    env = lambda k: os.environ.get(k, DEFAULTS[k])  # noqa: E731
    p = argparse.ArgumentParser(
        prog="wg-peer-whitelist",
        description="Keep WireGuard peer IPs on a CrowdSec whitelist. Every option can also be set via the WGPW_* env var shown.",
    )
    p.add_argument("--wg-cmd", default=env("WGPW_WG_CMD"), help="command printing `wg show all dump` [WGPW_WG_CMD]")
    p.add_argument("--wg-input", metavar="FILE", help="read dump from FILE ('-' = stdin) instead of running --wg-cmd")
    p.add_argument("--source", choices=("endpoints", "allowed-ips", "both"), default=env("WGPW_SOURCE"),
                   help="which peer addresses to whitelist [WGPW_SOURCE] (default: endpoints)")
    p.add_argument("--interface", action="append", default=[x for x in os.environ.get("WGPW_INTERFACES", "").replace(",", " ").split() if x],
                   help="only peers of this WG interface (repeatable) [WGPW_INTERFACES]")
    p.add_argument("--include-private", action="store_true", default=os.environ.get("WGPW_INCLUDE_PRIVATE") == "1",
                   help="also whitelist private/loopback/CGNAT addresses [WGPW_INCLUDE_PRIVATE=1]")
    p.add_argument("--max-handshake-age", type=int, default=int(os.environ.get("WGPW_MAX_HANDSHAKE_AGE", "0")),
                   help="seconds; skip peers without a handshake in this window (0 = keep all) [WGPW_MAX_HANDSHAKE_AGE]")
    p.add_argument("--extra", action="append", default=[os.environ["WGPW_EXTRA"]] if os.environ.get("WGPW_EXTRA") else [],
                   help="additional static IP/CIDR to whitelist (repeatable, comma-separated ok) [WGPW_EXTRA]")
    p.add_argument("--backend", choices=("parser", "allowlist"), default=env("WGPW_BACKEND"), help="[WGPW_BACKEND]")
    p.add_argument("--output", default=env("WGPW_OUTPUT"), help="parser backend: YAML path [WGPW_OUTPUT]")
    p.add_argument("--parser-name", default=env("WGPW_PARSER_NAME"), help="parser backend: parser name [WGPW_PARSER_NAME]")
    p.add_argument("--reload-cmd", default=env("WGPW_RELOAD_CMD"), help="run after a change ('' = none) [WGPW_RELOAD_CMD]")
    p.add_argument("--allowlist", default=env("WGPW_ALLOWLIST"), help="allowlist backend: list name [WGPW_ALLOWLIST]")
    p.add_argument("--cscli", default=env("WGPW_CSCLI"), help="cscli command [WGPW_CSCLI]")
    p.add_argument("--lock-file", default=env("WGPW_LOCK_FILE"), help="[WGPW_LOCK_FILE]")
    p.add_argument("--allow-empty", action="store_true", help="permit writing an empty whitelist (default: refuse)")
    p.add_argument("--dry-run", "-n", action="store_true", help="show what would change, write nothing")
    p.add_argument("--print", dest="print_only", action="store_true", help="print the generated YAML / value list and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def main(argv: Optional[Sequence[str]] = None, run=_run) -> int:
    args = build_parser().parse_args(argv)

    try:
        extra = parse_extra(args.extra)
    except ValueError as exc:
        log(f"invalid --extra: {exc}")
        return 2

    if args.wg_input:
        dump = sys.stdin.read() if args.wg_input == "-" else open(args.wg_input, encoding="utf-8").read()
    else:
        try:
            dump = run(shlex.split(args.wg_cmd))
        except (OSError, subprocess.CalledProcessError) as exc:
            log(f"wg command failed, leaving whitelist untouched: {exc}")
            return 3

    peers = parse_dump(dump)
    entries = collect_entries(peers, args.source, args.include_private, args.max_handshake_age, args.interface)
    entries |= extra
    log(f"{len(peers)} peer(s) parsed, {len(entries)} whitelist entr{'y' if len(entries) == 1 else 'ies'}")

    if not entries and not args.allow_empty:
        log("no entries - refusing to write an empty whitelist (use --allow-empty)")
        return 4

    if args.print_only:
        if args.backend == "parser":
            sys.stdout.write(render_parser_yaml(entries, args.parser_name, "wireguard peer"))
        else:
            for n in sorted(entries, key=_sort_key):
                print(_value_str(n))
        return 0

    lock_fh = None
    if not args.dry_run:
        import fcntl  # POSIX only; imported lazily so tests run anywhere

        lock_fh = open(args.lock_file, "w")
        try:
            fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("another run holds the lock, skipping")
            return 0

    try:
        if args.backend == "allowlist":
            return sync_allowlist(args, entries, run)

        new = render_parser_yaml(entries, args.parser_name, "wireguard peer")
        old = ""
        if os.path.exists(args.output):
            with open(args.output, encoding="utf-8") as fh:
                old = fh.read()
            if old and not old.startswith(MANAGED_HEADER):
                log(f"{args.output} exists but is not managed by this tool - refusing to overwrite")
                return 5
        if old == new:
            log("whitelist up to date, nothing to do")
            return 0
        sys.stdout.write(unified_diff(old, new, args.output))
        if args.dry_run:
            log("dry-run: not writing, not reloading")
            return 0
        atomic_write(args.output, new)
        log(f"wrote {args.output}")
        if args.reload_cmd.strip():
            try:
                run(shlex.split(args.reload_cmd))
                log("crowdsec reloaded")
            except (OSError, subprocess.CalledProcessError) as exc:
                log(f"reload failed: {exc}")
                return 6
        return 0
    finally:
        if lock_fh:
            lock_fh.close()


if __name__ == "__main__":
    sys.exit(main())

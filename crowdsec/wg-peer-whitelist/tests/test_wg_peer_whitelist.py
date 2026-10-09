import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).parent
FIX = HERE / "fixtures"
SCRIPT = HERE.parent / "wg-peer-whitelist.py"

spec = importlib.util.spec_from_file_location("wpw", SCRIPT)
wpw = importlib.util.module_from_spec(spec)
sys.modules["wpw"] = wpw
spec.loader.exec_module(wpw)

DUMP = (FIX / "wg-show-all-dump.txt").read_text()


def fake_run(outputs):
    """Return a run() stub that records calls and answers from a dict keyed by argv[0:3]."""
    calls = []

    def run(cmd):
        calls.append(list(cmd))
        for key, value in outputs.items():
            if list(cmd[: len(key)]) == list(key):
                if isinstance(value, Exception):
                    raise value
                return value
        return ""

    run.calls = calls
    return run


# --- parsing ---------------------------------------------------------------
def test_parse_dump_skips_interface_lines_and_private_key():
    peers = wpw.parse_dump(DUMP)
    assert len(peers) == 7
    assert all("private" not in repr(p) for p in peers)


def test_endpoint_host_variants():
    assert wpw._endpoint_host("203.0.113.5:51820") == "203.0.113.5"
    assert wpw._endpoint_host("[2001:db8::1]:51820") == "2001:db8::1"
    assert wpw._endpoint_host("(none)") is None
    assert wpw._endpoint_host("garbage:1") is None


def test_single_interface_dump_8_fields():
    line = "PUB=\t(none)\t203.0.113.9:1\t10.0.0.9/32\t1700000000\t0\t0\toff\n"
    peers = wpw.parse_dump("PRIV\tPUB\t51820\toff\n" + line)
    assert [p.endpoint_ip for p in peers] == ["203.0.113.9"]


# --- selection -------------------------------------------------------------
def test_endpoints_default_skips_private_none_and_dedups():
    entries = wpw.collect_entries(wpw.parse_dump(DUMP), "endpoints", False, 0, [])
    assert sorted(map(str, entries)) == sorted(
        ["198.51.100.7/32", "203.0.113.10/32", "203.0.113.77/32", "2001:db8::1/128"]
    )


def test_never_whitelists_default_route():
    entries = wpw.collect_entries(wpw.parse_dump(DUMP), "allowed-ips", True, 0, [])
    assert "0.0.0.0/0" not in map(str, entries)
    with pytest.raises(ValueError):
        wpw.parse_extra(["0.0.0.0/0"])


def test_interface_filter():
    entries = wpw.collect_entries(wpw.parse_dump(DUMP), "endpoints", False, 0, ["wg1"])
    assert list(map(str, entries)) == ["203.0.113.77/32"]


def test_max_handshake_age():
    entries = wpw.collect_entries(wpw.parse_dump(DUMP), "endpoints", False, 60, [], now=1700000030)
    # 198.51.100.7 handshook 10000s earlier -> stale
    assert "198.51.100.7/32" not in map(str, entries)
    assert "203.0.113.10/32" in map(str, entries)


# --- rendering (golden files) ----------------------------------------------
@pytest.mark.parametrize(
    "argv,expected",
    [
        ([], "expected-endpoints.yaml"),
        (["--source", "both", "--include-private", "--extra", "203.0.113.0/28"], "expected-both-private-extra.yaml"),
    ],
)
def test_print_matches_golden(argv, expected, capsys):
    rc = wpw.main(["--wg-input", str(FIX / "wg-show-all-dump.txt"), "--print", *argv])
    assert rc == 0
    assert capsys.readouterr().out == (FIX / expected).read_text()


def test_cli_entrypoint_runs_as_script():
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "--wg-input", "-", "--print"],
        input=DUMP, capture_output=True, text=True, check=True,
    ).stdout
    assert out == (FIX / "expected-endpoints.yaml").read_text()


# --- parser backend: write / idempotence / safety --------------------------
needs_fcntl = pytest.mark.skipif(sys.platform == "win32", reason="flock is POSIX-only")


@needs_fcntl
def test_write_then_idempotent_and_reload_only_on_change(tmp_path):
    out = tmp_path / "wl.yaml"
    run = fake_run({("wg",): DUMP})
    base = ["--output", str(out), "--lock-file", str(tmp_path / "lock"), "--reload-cmd", "systemctl reload crowdsec"]
    assert wpw.main(base, run=run) == 0
    assert out.read_text() == (FIX / "expected-endpoints.yaml").read_text()
    assert ["systemctl", "reload", "crowdsec"] in run.calls
    run2 = fake_run({("wg",): DUMP})
    assert wpw.main(base, run=run2) == 0
    assert ["systemctl", "reload", "crowdsec"] not in run2.calls  # unchanged -> no reload


def test_dry_run_writes_nothing(tmp_path, capsys):
    out = tmp_path / "wl.yaml"
    rc = wpw.main(["--wg-input", str(FIX / "wg-show-all-dump.txt"), "--output", str(out), "--dry-run"],
                  run=fake_run({}))
    assert rc == 0 and not out.exists()
    assert '+    - "203.0.113.10"' in capsys.readouterr().out


def test_refuses_to_overwrite_unmanaged_file(tmp_path):
    out = tmp_path / "wl.yaml"
    out.write_text("name: someone/else\n")
    rc = wpw.main(["--wg-input", str(FIX / "wg-show-all-dump.txt"), "--output", str(out), "--dry-run"])
    assert rc == 5 and out.read_text() == "name: someone/else\n"


def test_wg_failure_leaves_file_untouched(tmp_path):
    out = tmp_path / "wl.yaml"
    out.write_text(wpw.MANAGED_HEADER + "old\n")
    run = fake_run({("wg",): subprocess.CalledProcessError(1, "wg")})
    assert wpw.main(["--output", str(out)], run=run) == 3
    assert out.read_text().endswith("old\n")


def test_refuses_empty_whitelist(tmp_path):
    empty = tmp_path / "dump.txt"
    empty.write_text("wg0\tPRIV\tPUB\t51820\toff\n")
    assert wpw.main(["--wg-input", str(empty), "--print"]) == 4
    assert wpw.main(["--wg-input", str(empty), "--print", "--allow-empty"]) == 0


def test_env_configuration(monkeypatch, capsys):
    monkeypatch.setenv("WGPW_EXTRA", "198.51.100.0/24")
    monkeypatch.setenv("WGPW_INTERFACES", "wg1")
    assert wpw.main(["--wg-input", str(FIX / "wg-show-all-dump.txt"), "--print"]) == 0
    out = capsys.readouterr().out
    assert '"203.0.113.77"' in out and '"198.51.100.0/24"' in out and '"203.0.113.10"' not in out


# --- allowlist backend -----------------------------------------------------
def test_allowlist_sync_add_remove():
    inspect = json.dumps({"name": "wireguard-peers", "items": [
        {"value": "203.0.113.10"}, {"value": "192.0.2.99"}]})
    run = fake_run({
        ("wg",): DUMP,
        ("cscli", "allowlists", "list"): json.dumps([{"name": "wireguard-peers"}]),
        ("cscli", "allowlists", "inspect"): inspect,
    })
    assert wpw.main(["--backend", "allowlist", "--lock-file", "/dev/null"] if sys.platform != "win32"
                    else ["--backend", "allowlist", "--dry-run"], run=run) == 0
    if sys.platform != "win32":
        add = [c for c in run.calls if c[1:3] == ["allowlists", "add"]][0]
        assert add[3] == "wireguard-peers"
        assert set(add[4:-2]) == {"198.51.100.7", "203.0.113.77", "2001:db8::1"}
        assert ["cscli", "allowlists", "remove", "wireguard-peers", "192.0.2.99"] in run.calls


def test_allowlist_dry_run_creates_nothing(capsys):
    run = fake_run({("wg",): DUMP, ("cscli", "allowlists", "list"): "[]"})
    assert wpw.main(["--backend", "allowlist", "--dry-run"], run=run) == 0
    assert not [c for c in run.calls if c[1:3] in (["allowlists", "create"], ["allowlists", "add"])]
    assert "+ 203.0.113.10" in capsys.readouterr().out

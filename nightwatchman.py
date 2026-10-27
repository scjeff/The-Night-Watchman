#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
The Night Watchman — flag Wi-Fi and Bluetooth devices that Kismet has
already heard whose name or vendor resembles a wireless camera or dash cam.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

WHAT IT DETECTS AND HOW
  It reads device metadata that a running Kismet server (REST API, default
  http://127.0.0.1:2501) or a finished .kismet log (SQLite, opened read-only)
  already holds: MAC/BSSID, SSID, Bluetooth advertised name, vendor name,
  channel, signal dBm, first/last seen, and device type. It compares the
  SSID / Bluetooth name and the vendor (OUI) against the editable regex
  watchlist in nightwatchman.json (Wolfbox, VIOFO, 70mai, Garmin, DDPAI,
  Rexing, YI, Wyze, Ring, Arlo, Hikvision, Dahua, IPC, CAM, DVR, DashCam, ...).
  It matches SSID / name / OUI patterns ONLY. It does not fingerprint
  traffic, decode payloads, or look at video. Each hit is a CANDIDATE with a
  confidence basis (name / bt_name / oui / model / name+oui / model+oui),
  and a signal trend (steady / varying) that is a hint only. Output never
  says "this is a camera". Attribution is left to site security or the
  investigating party.

PASSIVE AND RECEIVE-ONLY
  The Night Watchman never touches a radio. It sends no frames, does no
  active probing, injection, deauthentication, association, pairing, GATT
  reads, or packet / payload capture. Its only network traffic is HTTP to the
  Kismet server you name (localhost by default). Kismet itself should be run
  receive-only with packet logging off (see README, "Kismet configuration").
  The tool refuses to start if Kismet reports a pcap/packet log as active
  (or if that status is unverifiable), unless --allow-packet-logging-risk
  is set; the override is recorded in every output.

AUTHORIZATION / SCOPE ASSUMED
  Use it only on your own network and devices, or in an authorized survey
  under a written Rules of Engagement. It refuses to start without an ROE ID,
  an authorization reference, an operator name, and a YES acknowledgement
  (or --i-have-roe). The gate records the operator's attestation of
  authorization; it does not verify the ROE. An optional --scope-file
  (see scope.template.json) is hashed into the session; --strict-scope
  refuses on window/operator mismatch. Packet/pcap logging fails closed
  unless --allow-packet-logging-risk is set (and recorded). It does NOT
  replace the site owner's or operator's own approval before a receiver
  is brought into a controlled area.

DEPENDENCIES
  Python 3.9+ standard library only (no pip packages).
  Live mode: a Kismet server you already run (Kismet is not installed or
  started by this tool), with credentials in KISMET_USER / KISMET_PASS or an
  API token in KISMET_API_TOKEN. Credentials are never printed or written.
  Offline: --kismetdb FILE.kismet, or --demo (bundled fixture, no Kismet).

    python3 nightwatchman.py --self-test
    python3 nightwatchman.py --demo --roe-id DEMO-ROE --auth-ref DEMO-AUTH \\
        --operator "Jane Doe" --i-have-roe
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

TOOL_NAME = "The Night Watchman"
TOOL_ID = "nightwatchman"
VERSION = "0.3.0"
MIN_PYTHON = (3, 9)
DEFAULT_KISMET_URL = "http://127.0.0.1:2501"
DEFAULT_CONFIG = "nightwatchman.json"
DEMO_FIXTURE = "fixtures/demo_kismet_polls.json"

MAX_PATTERN_LEN = 200
MAX_PATTERNS = 500
MAX_GATE_LEN = 128
MAX_SCOPE_BYTES = 1_000_000
# SSIDs are at most 32 octets; BT names at most 248. Matching runs on a
# bounded string so a hostile name cannot make a regex run long.
MAX_MATCH_LEN = 248
MAX_DISPLAY_LEN = 64

CANDIDATE_WORDING = {
    "name": "candidate: SSID resembles a camera/dash cam",
    "bt_name": "candidate: Bluetooth name resembles a camera/dash cam",
    "model": "candidate: SSID/name resembles a listed camera/dash cam model string",
    "oui": "candidate: vendor (OUI) resembles a camera/dash cam maker",
    "name+oui": "candidate: SSID/name and vendor (OUI) resemble a camera/dash cam",
    "model+oui": "candidate: model string and vendor (OUI) resemble a camera/dash cam",
}
CONFIDENCE_NOTE = {
    "name": "low: name match only; names are user-settable and spoofable",
    "bt_name": "low: Bluetooth name match only; names are user-settable",
    "model": "low: model-name match only; listing model strings are unverified as SSID/BT names",
    "oui": "low: vendor match only; the vendor also makes non-camera products",
    "name+oui": "medium: name and vendor agree; still unverified",
    "model+oui": "low-medium: model string and vendor agree; model string still unverified as SSID",
}
HYPOTHESIS_LINE = "HYPOTHESIS, NOT A FINDING. Pattern match on SSID/name/OUI metadata only."
ATTRIBUTION_LINE = (
    "Attribution of any device to a person, vehicle, or purpose is left to "
    "site security or the investigating party."
)
ROE_LINE = (
    "Authorized use only: written authorization / rules of engagement "
    "required; metadata only; any receiver brought into a controlled area "
    "needs the site owner's or operator's own approval first."
)
ATTESTATION_LINE = (
    "The gate records the operator's attestation of authorization. "
    "It does not verify the ROE."
)
INTEGRITY_LINE = (
    "0444 + SHA256SUMS supports integrity but is NOT tamper-proof; "
    "record the SHA256SUMS digest out-of-band (ROE log or custodian handoff)."
)
PACKET_OVERRIDE_LINE = (
    "OPERATOR OVERRIDE: --allow-packet-logging-risk was set; "
    "packet/pcap logging was present or unverifiable."
)

# Brand-ish labels kept under --profile strict (generic IPC/CAM/DVR/DashCam/FPV dropped).
STRICT_NAME_LABELS = frozenset({
    "Wolfbox dash cam", "VIOFO dash cam", "70mai dash cam", "Garmin dash cam",
    "DDPAI dash cam", "Rexing dash cam", "Nextbase dash cam", "Thinkware dash cam",
    "BlackVue dash cam", "Vantrue dash cam", "YI camera", "Wyze camera",
    "Ring camera", "Arlo camera", "Hikvision camera", "Dahua camera", "Reolink camera",
})
PCAP_LOG_TYPES = frozenset({"pcapng", "pcapppi", "pcap"})
PCAP_PATH_SUFFIXES = (".pcap", ".pcapng")

DISCLAIMER = """\
  AUTHORIZED USE ONLY
  The Night Watchman reads device metadata Kismet already collected and flags
  names or vendors that resemble wireless cameras or dash cams.

  Run it only on your own network and devices, or under a signed Rules of
  Engagement. It does not replace the site owner's or operator's own approval
  before a receiver is brought into a controlled area. Unauthorized
  interception can be a crime.
  The authors assume no liability for misuse.

  Passive: no transmit, probing, injection, deauthentication, association,
  pairing, or packet/payload capture. SSID/name/OUI pattern matching only.
"""

# C0/C1 controls, DEL, and Unicode format characters (bidi overrides,
# zero-width) are removed before a string is shown or written.
_ANSI_RE = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_CSV_LEADERS = ("=", "+", "-", "@", "\t", "\r", "|", "%")
# Crude catastrophic-backtracking screen: a group containing a quantifier
# that is itself quantified, e.g. (a+)+ or (\w*)*.
_NESTED_QUANT_RE = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*[+*{]")


def log(msg: str, level: str = "info") -> None:
    tag = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[x]"}.get(level, "[*]")
    stream = sys.stderr if level in {"warn", "err"} else sys.stdout
    print(f"{tag} {msg}", file=stream, flush=True)


def utc_iso(ts: Optional[float] = None) -> str:
    if ts is None:
        ts = time.time()
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Untrusted text handling
# --------------------------------------------------------------------------


def sanitize_text(value: Any, max_len: int = MAX_DISPLAY_LEN) -> str:
    """Make attacker-controlled text safe to print: no controls, no bidi, bounded."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="replace")
    text = str(value)
    text = _ANSI_RE.sub("", text)
    text = _CTRL_RE.sub("", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = text.strip()
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def csv_safe(value: Any) -> str:
    """Guard spreadsheet formula injection on an already sanitized string."""
    text = "" if value is None else str(value)
    if text and text.startswith(_CSV_LEADERS):
        return "'" + text
    return text


def raw_hex(value: Any) -> str:
    """Exact bytes of an untrusted name, for evidence, in a form that cannot execute."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return str(value).encode("utf-8", errors="surrogatepass").hex()


def normalize_mac(value: Any) -> str:
    hexmac = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    if len(hexmac) != 12:
        return ""
    return ":".join(hexmac[i : i + 2] for i in range(0, 12, 2))


def is_locally_administered(mac: str) -> bool:
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Watchlist
# --------------------------------------------------------------------------


class ConfigError(ValueError):
    pass


@dataclass
class Pattern:
    label: str
    regex: "re.Pattern[str]"


@dataclass
class Watchlist:
    ssid: list[Pattern]
    vendor: list[Pattern]
    model: list[Pattern]
    oui: dict[str, str]
    trend_min_samples: int = 4
    trend_varying_db: float = 8.0
    trend_steady_db: float = 4.0
    sha256: str = ""
    source: str = ""
    overlay_source: str = ""
    overlay_sha256: str = ""


def validate_pattern(raw: Any, where: str) -> Pattern:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: each entry must be an object with label and pattern")
    label = raw.get("label")
    pattern = raw.get("pattern")
    if not isinstance(label, str) or not label.strip():
        raise ConfigError(f"{where}: label must be a non-empty string")
    if not isinstance(pattern, str) or not pattern:
        raise ConfigError(f"{where}: pattern must be a non-empty string")
    if len(pattern) > MAX_PATTERN_LEN:
        raise ConfigError(f"{where}: pattern longer than {MAX_PATTERN_LEN} characters")
    if _NESTED_QUANT_RE.search(pattern):
        raise ConfigError(f"{where}: nested quantifier (catastrophic backtracking risk): {pattern!r}")
    if re.search(r"\\[1-9]|\(\?P=", pattern):
        raise ConfigError(f"{where}: backreferences are not allowed: {pattern!r}")
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ConfigError(f"{where}: invalid regex {pattern!r}: {exc}") from None
    if compiled.search(""):
        raise ConfigError(f"{where}: pattern matches the empty string and would flag everything: {pattern!r}")
    return Pattern(label=sanitize_text(label, 80), regex=compiled)


def parse_watchlist(data: Any, *, sha256: str = "", source: str = "") -> Watchlist:
    if not isinstance(data, dict):
        raise ConfigError("config root must be a JSON object")
    out: dict[str, list[Pattern]] = {}
    for key in ("ssid_patterns", "vendor_patterns", "model_patterns"):
        items = data.get(key, [])
        if not isinstance(items, list):
            raise ConfigError(f"{key} must be a list")
        if len(items) > MAX_PATTERNS:
            raise ConfigError(f"{key}: more than {MAX_PATTERNS} entries")
        out[key] = [validate_pattern(item, f"{key}[{i}]") for i, item in enumerate(items)]
    oui: dict[str, str] = {}
    prefixes = data.get("oui_prefixes", [])
    if not isinstance(prefixes, list):
        raise ConfigError("oui_prefixes must be a list")
    for i, item in enumerate(prefixes):
        if not isinstance(item, dict):
            raise ConfigError(f"oui_prefixes[{i}] must be an object with prefix and label")
        hexp = re.sub(r"[^0-9A-Fa-f]", "", str(item.get("prefix", ""))).upper()
        if len(hexp) not in (6, 7, 9):
            raise ConfigError(f"oui_prefixes[{i}]: prefix must be 24, 28, or 36 bits")
        oui[hexp] = sanitize_text(item.get("label") or hexp, 80)
    if (
        not out["ssid_patterns"]
        and not out["vendor_patterns"]
        and not out["model_patterns"]
        and not oui
    ):
        raise ConfigError("watchlist is empty")
    trend = data.get("trend", {}) or {}
    if not isinstance(trend, dict):
        raise ConfigError("trend must be an object")
    try:
        wl = Watchlist(
            ssid=out["ssid_patterns"],
            vendor=out["vendor_patterns"],
            model=out["model_patterns"],
            oui=oui,
            trend_min_samples=max(2, int(trend.get("min_samples", 4))),
            trend_varying_db=float(trend.get("varying_db", 8.0)),
            trend_steady_db=float(trend.get("steady_db", 4.0)),
            sha256=sha256,
            source=source,
        )
    except (TypeError, ValueError):
        raise ConfigError("trend values must be numbers") from None
    if wl.trend_steady_db > wl.trend_varying_db:
        raise ConfigError("trend.steady_db must not exceed trend.varying_db")
    return wl


def _read_json_object(path: Path) -> tuple[dict, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc.strerror}") from None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"config {path} is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"config {path} root must be a JSON object")
    return data, raw


def merge_watchlist_dicts(base: dict, extra: dict) -> dict:
    """Append pattern lists and OUI prefixes from an overlay onto the base config."""
    merged = dict(base)
    for key in ("ssid_patterns", "vendor_patterns", "model_patterns", "oui_prefixes"):
        base_list = list(base.get(key) or [])
        extra_list = extra.get(key, [])
        if extra_list is None:
            extra_list = []
        if not isinstance(extra_list, list):
            raise ConfigError(f"overlay {key} must be a list")
        merged[key] = base_list + extra_list
    if "trend" in extra and extra["trend"] is not None:
        if not isinstance(extra["trend"], dict):
            raise ConfigError("overlay trend must be an object")
        trend = dict(base.get("trend") or {})
        trend.update(extra["trend"])
        merged["trend"] = trend
    return merged


def load_watchlist(path: Path, *, overlay: Optional[Path] = None) -> Watchlist:
    """Load the base watchlist, optionally merging a local overlay.

    Overlay resolution: explicit ``overlay`` path, else ``nightwatchman.local.json``
    next to the base file when that file exists. Overlay patterns are validated
    with the same rules as the base file.
    """
    data, raw = _read_json_object(path)
    overlay_path: Optional[Path] = None
    overlay_raw = b""
    if overlay is not None:
        overlay_path = overlay
    else:
        candidate = path.with_name("nightwatchman.local.json")
        if candidate.is_file():
            overlay_path = candidate
    if overlay_path is not None:
        extra, overlay_raw = _read_json_object(overlay_path)
        data = merge_watchlist_dicts(data, extra)
    # Base file hash stays on config_sha256; overlay hash is separate so
    # config_used.json (a copy of the base) still verifies.
    wl = parse_watchlist(
        data,
        sha256=hashlib.sha256(raw).hexdigest(),
        source=str(path),
    )
    if overlay_path is not None:
        wl.overlay_source = str(overlay_path.resolve())
        wl.overlay_sha256 = hashlib.sha256(overlay_raw).hexdigest()
    return wl


def apply_profile(wl: Watchlist, profile: str) -> Watchlist:
    """strict = brand names + vendor only; broad = full watchlist (default).

    Model-string patterns from an overlay are broad-only; they are dropped under
    strict so a survey that wants brands does not keep unverified model tokens.
    """
    if profile == "broad":
        return wl
    if profile != "strict":
        raise ConfigError(f"unknown profile {profile!r}")
    return Watchlist(
        ssid=[p for p in wl.ssid if p.label in STRICT_NAME_LABELS],
        vendor=list(wl.vendor),
        model=[],  # model strings stay out of strict
        oui=dict(wl.oui),
        trend_min_samples=wl.trend_min_samples,
        trend_varying_db=wl.trend_varying_db,
        trend_steady_db=wl.trend_steady_db,
        sha256=wl.sha256,
        source=wl.source,
        overlay_source=wl.overlay_source,
        overlay_sha256=wl.overlay_sha256,
    )


def load_ieee_table(path: Optional[Path]) -> dict[str, str]:
    """Optional prefix,vendor CSV (the same file The Magic Flute downloads)."""
    table: dict[str, str] = {}
    if not path or not path.is_file():
        return table
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = [f.strip().lower() for f in (reader.fieldnames or [])]
        if "prefix" not in fields or "vendor" not in fields:
            return table
        for row in reader:
            prefix = re.sub(r"[^0-9A-Fa-f]", "", row.get("prefix") or "").upper()
            vendor = (row.get("vendor") or "").strip()
            if prefix and vendor:
                table[prefix] = vendor
    return table


def lookup_prefix(mac: str, table: dict[str, str]) -> str:
    hexmac = mac.replace(":", "")
    for width in (9, 7, 6):
        hit = table.get(hexmac[:width])
        if hit:
            return hit
    return ""


# --------------------------------------------------------------------------
# Kismet device records
# --------------------------------------------------------------------------

# Aliased field simplification for /devices/last-time/<ts>/devices.json.
# Same approach as The Magic Flute. dot11 fields are dropped if rejected.
KISMET_FIELDS = [
    ["kismet.device.base.macaddr", "mac"],
    ["kismet.device.base.phyname", "phy"],
    ["kismet.device.base.type", "type"],
    ["kismet.device.base.channel", "channel"],
    ["kismet.device.base.frequency", "frequency"],
    ["kismet.device.base.first_time", "first_time"],
    ["kismet.device.base.last_time", "last_time"],
    ["kismet.device.base.manuf", "manuf"],
    ["kismet.device.base.commonname", "commonname"],
    ["kismet.device.base.name", "name"],
    ["kismet.device.base.signal/kismet.common.signal.last_signal", "signal"],
    ["dot11.device/dot11.device.last_beaconed_ssid_record/dot11.advertisedssid.ssid", "ssid"],
    ["dot11.device/dot11.device.last_bssid", "last_bssid"],
]
KISMET_FIELDS_BASIC = [f for f in KISMET_FIELDS if not f[0].startswith("dot11.")]


def _dig(obj: Any, *path: str) -> Any:
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


@dataclass
class Observation:
    mac: str
    phy: str
    dtype: str
    ssid_raw: str
    btname_raw: str
    bssid: str
    vendor: str
    channel: str
    signal_dbm: Optional[float]
    first_time: Optional[float]
    last_time: Optional[float]
    # Extra beaconed SSIDs or Bluetooth names on the same device. Probe
    # requests are not stored: a phone that looked for a camera SSID is not
    # the camera.
    ssid_extra: tuple[str, ...] = ()
    btname_extra: tuple[str, ...] = ()


def _num(value: Any) -> Optional[float]:
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out


def _plain_text(value: Any) -> str:
    """Names are text. Kismet uses a number (usually 0) when a device has no SSID."""
    if value is None or isinstance(value, (dict, list, bool, int, float)):
        return ""
    return str(value).strip()


def _unique_text(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        if value and value not in out:
            out.append(value)
    return out


def _not_this_mac(text: str, mac: str) -> bool:
    return bool(text) and normalize_mac(text) != mac


def _is_bluetooth(phy: str, dev: dict) -> bool:
    folded = phy.lower()
    if "bluetooth" in folded or "btle" in folded or folded in {"bt", "br/edr"}:
        return True
    return isinstance(dev.get("bluetooth.device"), dict) or isinstance(dev.get("btle.device"), dict)


def _beacon_ssids(dev: dict) -> list[str]:
    """Beaconed / advertised SSIDs only. Client probe lists are left alone."""
    found: list[str] = []
    if "ssid" in dev:
        text = _plain_text(dev.get("ssid"))
        if text:
            found.append(text)
    dot11 = dev.get("dot11.device")
    if isinstance(dot11, dict):
        last = dot11.get("dot11.device.last_beaconed_ssid_record")
        if isinstance(last, dict):
            text = _plain_text(last.get("dot11.advertisedssid.ssid"))
            if text:
                found.append(text)
        amap = dot11.get("dot11.device.advertised_ssid_map")
        records: list[Any]
        if isinstance(amap, dict):
            records = list(amap.values())
        elif isinstance(amap, list):
            records = amap
        else:
            records = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            text = _plain_text(rec.get("dot11.advertisedssid.ssid"))
            if text:
                found.append(text)
    return _unique_text(found)


def _signal_dbm(value: Any) -> Optional[float]:
    if isinstance(value, dict):
        value = value.get("kismet.common.signal.last_signal")
    sig = _num(value)
    # Kismet stores 0 when it has no dBm sample. Positive values are not dBm.
    if sig is None or sig >= 0 or sig < -120:
        return None
    return sig


def parse_device(dev: Any) -> Optional[Observation]:
    """Accept either an aliased simplified record or a full Kismet device JSON."""
    if not isinstance(dev, dict):
        return None

    def pick(alias: str, *full: str) -> Any:
        if alias in dev:
            return dev.get(alias)
        return _dig(dev, *full) if full else None

    mac = normalize_mac(pick("mac", "kismet.device.base.macaddr"))
    if not mac:
        return None
    phy = str(pick("phy", "kismet.device.base.phyname") or "")
    dtype = str(pick("type", "kismet.device.base.type") or "")
    is_bt = _is_bluetooth(phy, dev)
    commonname = _plain_text(pick("commonname", "kismet.device.base.commonname"))
    name = _plain_text(pick("name", "kismet.device.base.name"))
    beaconed = [] if is_bt else _beacon_ssids(dev)
    bt_names: list[str] = []
    if is_bt:
        bt = dev.get("bluetooth.device")
        if isinstance(bt, dict):
            for key in ("bluetooth.device.device_name", "bluetooth.device.name"):
                text = _plain_text(bt.get(key))
                if _not_this_mac(text, mac):
                    bt_names.append(text)
        btle = dev.get("btle.device")
        if isinstance(btle, dict):
            for key, value in btle.items():
                if "name" in str(key).lower():
                    text = _plain_text(value)
                    if _not_this_mac(text, mac):
                        bt_names.append(text)
        for cand in (name, commonname):
            if _not_this_mac(cand, mac):
                bt_names.append(cand)
        bt_names = _unique_text(bt_names)
    elif not beaconed:
        # Basic-field fallback (no dot11 paths): Kismet's commonname / name
        # usually carries the SSID for an AP. Skip it when it is only the MAC.
        for cand in (commonname, name):
            if _not_this_mac(cand, mac):
                beaconed.append(cand)
                break
    last_bssid = normalize_mac(pick("last_bssid", "dot11.device", "dot11.device.last_bssid"))
    if not last_bssid or last_bssid == "00:00:00:00:00:00":
        last_bssid = mac if ("ap" in dtype.lower() and not is_bt) else ""
    freq = _num(pick("frequency", "kismet.device.base.frequency"))
    channel = str(pick("channel", "kismet.device.base.channel") or "")
    # kismet.device.base.frequency is kilohertz (2412000 for 2412 MHz).
    if not channel and freq:
        channel = f"{freq / 1000.0:.0f} MHz" if freq > 100000 else f"{freq:.0f} MHz"
    return Observation(
        mac=mac,
        phy=phy,
        dtype=dtype,
        ssid_raw=beaconed[0] if beaconed else "",
        btname_raw=bt_names[0] if bt_names else "",
        bssid=last_bssid,
        vendor=str(pick("manuf", "kismet.device.base.manuf") or ""),
        channel=channel,
        signal_dbm=_signal_dbm(pick("signal", "kismet.device.base.signal", "kismet.common.signal.last_signal")),
        first_time=_num(pick("first_time", "kismet.device.base.first_time")),
        last_time=_num(pick("last_time", "kismet.device.base.last_time")),
        ssid_extra=tuple(beaconed[1:]),
        btname_extra=tuple(bt_names[1:]),
    )


# --------------------------------------------------------------------------
# Classification and trend
# --------------------------------------------------------------------------


@dataclass
class Candidate:
    mac: str
    phy: str
    dtype: str
    ssid_raw: str
    btname_raw: str
    bssid: str
    vendor: str
    channel: str
    basis: str
    name_label: str
    vendor_label: str
    first_time: Optional[float]
    last_time: Optional[float]
    name_kind: str = ""
    samples: deque = field(default_factory=lambda: deque(maxlen=120))

    @property
    def last_dbm(self) -> Optional[float]:
        return self.samples[-1][1] if self.samples else None

    @property
    def max_dbm(self) -> Optional[float]:
        return max((s[1] for s in self.samples), default=None)


def combine_basis(name_label: str, name_kind: str, vendor_label: str) -> Optional[str]:
    if name_label and vendor_label:
        if name_kind == "model":
            return "model+oui"
        return "name+oui"
    if name_label:
        return name_kind or "name"
    if vendor_label:
        return "oui"
    return None


def _match_patterns(texts: Iterable[str], patterns: list[Pattern]) -> tuple[str, str]:
    for text in texts:
        if not text:
            continue
        probe = sanitize_text(text, MAX_MATCH_LEN)
        for pat in patterns:
            if pat.regex.search(probe):
                return pat.label, text
    return "", ""


def classify(obs: Observation, wl: Watchlist, ieee: dict[str, str]) -> Optional[tuple[str, str, str, str, str, str]]:
    """Return (basis, name_label, name_kind, vendor_label, vendor_text, matched_text) or None."""
    name_label = ""
    name_kind = ""
    matched_text = ""
    # Brand / generic SSID and Bluetooth-name patterns first.
    for kind, texts in (
        ("name", (obs.ssid_raw, *obs.ssid_extra)),
        ("bt_name", (obs.btname_raw, *obs.btname_extra)),
    ):
        label, text = _match_patterns(texts, wl.ssid)
        if label:
            name_label, name_kind, matched_text = label, kind, text
            break
    # Optional model-string patterns (usually from a local overlay). Used only
    # when no brand/generic name matched. Listing model names are unverified
    # as SSID or Bluetooth strings.
    if not name_label:
        label, text = _match_patterns(
            (obs.ssid_raw, *obs.ssid_extra, obs.btname_raw, *obs.btname_extra),
            wl.model,
        )
        if label:
            name_label, name_kind, matched_text = label, "model", text
    vendor_text = obs.vendor
    if (not vendor_text or vendor_text.lower() == "unknown") and not is_locally_administered(obs.mac):
        vendor_text = lookup_prefix(obs.mac, ieee) or vendor_text
    vendor_label = lookup_prefix(obs.mac, wl.oui) if wl.oui else ""
    if not vendor_label and vendor_text:
        probe = sanitize_text(vendor_text, MAX_MATCH_LEN)
        for pat in wl.vendor:
            if pat.regex.search(probe):
                vendor_label = pat.label
                break
    basis = combine_basis(name_label, name_kind, vendor_label)
    if basis is None:
        return None
    return basis, name_label, name_kind, vendor_label, vendor_text, matched_text


def signal_trend(samples: Iterable[tuple[float, float]], wl: Watchlist) -> str:
    """Hint only: spread of RSSI samples. Multipath and the surveyor moving also change it."""
    values = [s[1] for s in samples]
    if len(values) < wl.trend_min_samples:
        return "insufficient samples"
    spread = max(values) - min(values)
    if spread >= wl.trend_varying_db:
        return f"varying ({spread:.0f} dB spread; source or surveyor may be moving)"
    if spread <= wl.trend_steady_db:
        return f"steady ({spread:.0f} dB spread; possibly stationary)"
    return f"mixed ({spread:.0f} dB spread)"


class Tracker:
    def __init__(self, wl: Watchlist, ieee: dict[str, str]) -> None:
        self.wl = wl
        self.ieee = ieee
        self.candidates: dict[str, Candidate] = {}
        self.devices_seen: set[str] = set()

    def ingest(self, obs: Observation, now: float) -> Optional[Candidate]:
        self.devices_seen.add(obs.mac)
        hit = classify(obs, self.wl, self.ieee)
        cand = self.candidates.get(obs.mac)
        if hit is None and cand is None:
            return None
        if cand is None:
            basis, nlabel, nkind, vlabel, vtext, matched = hit  # type: ignore[misc]
            if matched and nkind == "bt_name":
                obs = Observation(**{**obs.__dict__, "btname_raw": matched})
            elif matched and nkind in {"name", "model"}:
                obs = Observation(**{**obs.__dict__, "ssid_raw": matched})
            cand = Candidate(
                mac=obs.mac, phy=obs.phy, dtype=obs.dtype, ssid_raw=obs.ssid_raw,
                btname_raw=obs.btname_raw, bssid=obs.bssid, vendor=vtext,
                channel=obs.channel, basis=basis, name_label=nlabel,
                vendor_label=vlabel, first_time=obs.first_time, last_time=obs.last_time,
                name_kind=nkind,
            )
            self.candidates[obs.mac] = cand
        else:
            if hit is not None:
                _, nlabel, nkind, vlabel, vtext, matched = hit
                if matched and nkind == "bt_name":
                    obs = Observation(**{**obs.__dict__, "btname_raw": matched})
                elif matched and nkind in {"name", "model"}:
                    obs = Observation(**{**obs.__dict__, "ssid_raw": matched})
                # Labels are sticky: a later hit adds evidence, it never erases
                # an earlier name or vendor match. Basis is recomputed from both.
                # Prefer a later brand/strict name over an earlier generic one
                # (e.g. "Generic camera" -> "Wolfbox dash cam").
                if nlabel:
                    if not cand.name_label:
                        cand.name_label, cand.name_kind = nlabel, nkind
                    elif (
                        cand.name_label not in STRICT_NAME_LABELS
                        and nlabel in STRICT_NAME_LABELS
                    ):
                        cand.name_label, cand.name_kind = nlabel, nkind
                if vlabel and not cand.vendor_label:
                    cand.vendor_label = vlabel
                if vtext and vtext.lower() != "unknown":
                    cand.vendor = vtext
                elif not cand.vendor:
                    cand.vendor = vtext
                cand.basis = combine_basis(cand.name_label, cand.name_kind, cand.vendor_label) or cand.basis
            cand.ssid_raw = obs.ssid_raw or cand.ssid_raw
            cand.btname_raw = obs.btname_raw or cand.btname_raw
            cand.bssid = obs.bssid or cand.bssid
            cand.channel = obs.channel or cand.channel
            if obs.first_time and (not cand.first_time or obs.first_time < cand.first_time):
                cand.first_time = obs.first_time
            if obs.last_time and (not cand.last_time or obs.last_time > cand.last_time):
                cand.last_time = obs.last_time
        if obs.signal_dbm is not None:
            t = obs.last_time or now
            if not cand.samples or cand.samples[-1] != (t, obs.signal_dbm):
                cand.samples.append((t, obs.signal_dbm))
        return cand


# --------------------------------------------------------------------------
# Kismet REST client (read-only endpoints)
# --------------------------------------------------------------------------


class KismetError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None) -> None:
        super().__init__(message)
        self.status = status


class KismetClient:
    """Reads Kismet. Credentials come from the environment and are never echoed."""

    def __init__(self, base: str, *, user: str = "", password: str = "", token: str = "", timeout: float = 8.0) -> None:
        parsed = urllib.parse.urlsplit(base)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise KismetError("Kismet URL must be http(s)://host:port")
        if parsed.username or parsed.password:
            raise KismetError("put credentials in KISMET_USER/KISMET_PASS or KISMET_API_TOKEN, not the URL")
        self.base = base.rstrip("/")
        self.timeout = timeout
        self._headers = {"Accept": "application/json"}
        if token:
            # Kismet API keys are sent as the KISMET session cookie.
            self._headers["Cookie"] = f"KISMET={token}"
        elif user or password:
            cred = base64.b64encode(f"{user}:{password}".encode()).decode()
            self._headers["Authorization"] = f"Basic {cred}"

    @classmethod
    def from_env(cls, base: str) -> "KismetClient":
        return cls(
            base,
            user=os.environ.get("KISMET_USER", ""),
            password=os.environ.get("KISMET_PASS", ""),
            token=os.environ.get("KISMET_API_TOKEN", ""),
        )

    def describe(self) -> str:
        mode = "token" if "Cookie" in self._headers else ("basic" if "Authorization" in self._headers else "none")
        return f"{self.base} (auth: {mode})"

    def _open(self, path: str, data: Optional[bytes] = None, ctype: str = "", timeout: Optional[float] = None) -> Any:
        headers = dict(self._headers)
        if ctype:
            headers["Content-Type"] = ctype
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method="POST" if data is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout if timeout is None else timeout) as resp:
                raw = resp.read(64 * 1024 * 1024).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise KismetError(f"HTTP {code} from {path}", status=code) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise KismetError(f"cannot reach Kismet at {self.base}: {sanitize_text(reason, 120)}") from None
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise KismetError(f"non-JSON response from {path}") from None

    def get_json(self, path: str) -> Any:
        return self._open(path)

    def post_fields(self, path: str, payload: dict[str, Any], timeout: Optional[float] = None) -> Any:
        """POST a field view. Kismet 2026 accepts a JSON body; older builds want a form field."""
        raw = json.dumps(payload).encode()
        bodies = (
            (raw, "application/json"),
            (
                urllib.parse.urlencode({"json": raw.decode()}).encode(),
                "application/x-www-form-urlencoded",
            ),
        )
        errors: list[str] = []
        last_status: Optional[int] = None
        for body, ctype in bodies:
            try:
                return self._open(path, body, ctype, timeout=timeout)
            except KismetError as exc:
                last_status = exc.status
                errors.append(str(exc))
                # Auth and reachability failures are not a reason to try the other encoding.
                if exc.status not in {400, 404, 405, 415, 500}:
                    raise
        raise KismetError("Kismet POST failed: " + "; ".join(errors), status=last_status)


def _entry_log_type(entry: dict) -> str:
    """Log type from a flat field, or from Kismet 2026's nested type driver.

    The nested description often mentions the word "packet" for a metadata log.
    Only the class/type strings are read, not that description.
    """
    for key in ("kismet.logfile.type", "log_type", "type", "class", "logclass"):
        val = entry.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip().lower()
    driver = entry.get("kismet.log.type_driver")
    if isinstance(driver, dict):
        for key in ("kismet.logfile.type.class", "class", "type", "kismet.logfile.type.name"):
            val = driver.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip().lower()
    return ""


def _entry_log_path(entry: dict) -> str:
    for key, val in entry.items():
        if str(key).endswith("path") or str(key).endswith("log_path"):
            return str(val or "")
    return ""


def entry_is_pcap_log(entry: Any) -> bool:
    """True when a logging entry is a packet capture log.
    Uses type fields (pcapng / pcapppi / pcap) or a .pcap/.pcapng path suffix.
    Does NOT substring-search the whole JSON (avoids 'pcap disabled' false hits)."""
    if not isinstance(entry, dict):
        return False
    if _entry_log_type(entry) in PCAP_LOG_TYPES:
        return True
    path = _entry_log_path(entry).lower()
    return any(path.endswith(suf) for suf in PCAP_PATH_SUFFIXES)


def packet_logging_warnings_from_active(active: Any) -> list[str]:
    """Look for pcap / packet logs in /logging/active.json."""
    warnings: list[str] = []
    if isinstance(active, list):
        entries = active
    elif isinstance(active, dict) and active:
        # Some builds wrap under a key; prefer a list value if present.
        nested = None
        for v in active.values():
            if isinstance(v, list):
                nested = v
                break
        entries = nested if nested is not None else [active]
    else:
        entries = []
    for entry in entries:
        if entry_is_pcap_log(entry):
            path = sanitize_text(_entry_log_path(entry), 160) if isinstance(entry, dict) else ""
            warnings.append(
                "Kismet reports an active pcap/packet log"
                + (f": {path}" if path else "")
                + ". Packet capture is out of scope; disable it (README, Kismet configuration)."
            )
    return warnings


class PacketLoggingRisk(Exception):
    """Raised when packet logging is present or unverifiable and no override was given."""

    def __init__(self, reasons: list[str]) -> None:
        self.reasons = list(reasons)
        super().__init__("; ".join(reasons))


def check_kismet_logging(client: KismetClient) -> list[str]:
    """Return packet-logging risk strings. An unreadable endpoint is itself a risk."""
    try:
        active = client.get_json("/logging/active.json")
    except KismetError as exc:
        return [
            f"Could not read /logging/active.json ({exc}); "
            "pcap/packet logging status is unverifiable."
        ]
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return [
            f"Could not parse /logging/active.json ({sanitize_text(exc, 80)}); "
            "pcap/packet logging status is unverifiable."
        ]
    # A non-list / non-dict body is treated as unverifiable.
    if active is None or (not isinstance(active, (list, dict))):
        return ["Could not parse /logging/active.json (unexpected shape); pcap/packet logging status is unverifiable."]
    return packet_logging_warnings_from_active(active)


def enforce_packet_logging_gate(risks: list[str], allow: bool) -> list[str]:
    """Fail closed unless --allow-packet-logging-risk is set. Returns notices for the session."""
    if not risks:
        return []
    if allow:
        return [PACKET_OVERRIDE_LINE] + risks
    raise PacketLoggingRisk(risks)


def _as_device_list(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "mac" in data or "kismet.device.base.macaddr" in data:
            return [data]
        for value in data.values():
            if isinstance(value, list):
                return value
    return []


class LiveSource:
    def __init__(self, client: KismetClient, start: float) -> None:
        self.client = client
        self.since = max(int(start) - 30, 0)
        self.fields = KISMET_FIELDS
        self._bootstrapped = False

    def poll(self) -> list[Any]:
        # The first poll reads every device the server already holds. Later
        # polls ask for devices heard in the last few seconds, with overlap.
        stamp = 0 if not self._bootstrapped else max(self.since, 0)
        path = f"/devices/last-time/{stamp}/devices.json"
        try:
            data = self.client.post_fields(path, {"fields": self.fields}, timeout=30)
        except KismetError as exc:
            if exc.status in {400, 500} and self.fields is not KISMET_FIELDS_BASIC:
                log(
                    "Kismet rejected the dot11 fields; retrying with base fields; "
                    "SSID taken from commonname/name if present.",
                    "warn",
                )
                self.fields = KISMET_FIELDS_BASIC
                data = self.client.post_fields(path, {"fields": self.fields}, timeout=30)
            else:
                raise
        self._bootstrapped = True
        self.since = int(time.time()) - 10
        return _as_device_list(data)


def _open_kismetdb(path: Path) -> sqlite3.Connection:
    try:
        return sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise KismetError(f"cannot open {path}: {exc}") from None


def kismetdb_risks(path: Path) -> list[str]:
    """Count packet rows only. Device JSON is not loaded until the gate allows it."""
    conn = _open_kismetdb(path)
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "devices" not in tables:
            raise KismetError(f"{path} has no devices table; is it a .kismet log?")
        warnings: list[str] = []
        # Table names are fixed literals, not user input.
        for tbl, noun in (
            ("packets", "logged packets"),
            ("data", "logged data-packet rows"),
        ):
            if tbl not in tables:
                continue
            try:
                n = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
            except sqlite3.Error:
                n = 0
            if n:
                warnings.append(
                    f"{path.name} contains {n} {noun}. This tool does not read them; "
                    "future surveys should set kis_log_packets=false and kis_log_data_packets=false."
                )
        return warnings
    except sqlite3.Error as exc:
        raise KismetError(f"cannot read {path}: {exc}") from None
    finally:
        conn.close()


def read_kismetdb_devices(path: Path) -> list[Any]:
    """Device JSON from a .kismet log, opened read-only. Packet tables are not read."""
    conn = _open_kismetdb(path)
    try:
        out: list[Any] = []
        for (blob,) in conn.execute("SELECT device FROM devices"):
            if isinstance(blob, (bytes, bytearray)):
                blob = bytes(blob).decode("utf-8", errors="replace")
            try:
                out.append(json.loads(blob))
            except (TypeError, json.JSONDecodeError):
                continue
        return out
    except sqlite3.Error as exc:
        raise KismetError(f"cannot read {path}: {exc}") from None
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Authorization gate
# --------------------------------------------------------------------------


@dataclass
class Authorization:
    roe_id: str
    auth_ref: str
    operator: str
    scope_file: str = ""
    scope_sha256: str = ""
    acknowledged_at: str = ""
    allow_packet_logging_risk: bool = False
    profile: str = "broad"
    strict_scope: bool = False
    scope_check: dict = field(default_factory=dict)
    host_clock: dict = field(default_factory=dict)


class GateError(Exception):
    """Authorization or safety gate failure; main() exits 2."""


def _gate_value(name: str, value: Optional[str]) -> str:
    raw = (value or "").strip()
    clean = sanitize_text(raw, MAX_GATE_LEN)
    if not clean:
        raise GateError(f"[x] Refusing to start: {name} is required.")
    if clean != raw:
        raise GateError(f"[x] Refusing to start: {name} has control characters or is longer than {MAX_GATE_LEN} characters.")
    return clean


def parse_timedatectl_show(text: str) -> dict[str, str]:
    """Parse `timedatectl show` Key=value lines. Order is not the -p order."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            out[key] = value.strip()
    return out


def host_clock_state() -> dict[str, Any]:
    """Best-effort NTP / clock source. 'unknown' when timedatectl is unavailable."""
    out: dict[str, Any] = {
        "recorded_at_utc": utc_iso(),
        "ntp_synchronized": "unknown",
        "timezone": "unknown",
        "source": "unavailable",
    }
    timedatectl = shutil.which("timedatectl")
    if not timedatectl:
        return out
    try:
        proc = subprocess.run(
            [timedatectl, "show", "-p", "NTPSynchronized", "-p", "Timezone"],
            capture_output=True, text=True, timeout=3, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return out
    if proc.returncode != 0:
        return out
    vals = parse_timedatectl_show(proc.stdout)
    ntp = vals.get("NTPSynchronized", "").lower()
    if ntp in {"yes", "true", "1"}:
        out["ntp_synchronized"] = "yes"
        out["source"] = "timedatectl"
    elif ntp in {"no", "false", "0"}:
        out["ntp_synchronized"] = "no"
        out["source"] = "timedatectl"
    elif ntp:
        out["ntp_synchronized"] = sanitize_text(ntp, 32)
        out["source"] = "timedatectl"
    if vals.get("Timezone"):
        out["timezone"] = sanitize_text(vals["Timezone"], 64)
        out["source"] = "timedatectl"
    return out


def parse_scope_document(data: bytes, path: Path) -> dict[str, Any]:
    """Parse a scope file. JSON (scope.template.json shape) preferred; plain text allowed."""
    text = data.decode("utf-8", errors="replace").strip()
    if not text:
        raise GateError("[x] Refusing to start: scope file is empty.")
    doc: dict[str, Any]
    if text[:1] in "{[":
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError as exc:
            raise GateError(f"[x] Refusing to start: scope file is not valid JSON: {exc}") from None
        if not isinstance(loaded, dict):
            raise GateError("[x] Refusing to start: scope JSON root must be an object.")
        doc = loaded
    else:
        # Free-form text scope: hash is recorded; structured checks are skipped.
        return {
            "format": "text",
            "protocols": [],
            "location": "",
            "authorized_operators": [],
            "window_start_utc": "",
            "window_end_utc": "",
            "raw_sha256": hashlib.sha256(data).hexdigest(),
            "path": str(path.resolve()),
        }
    protocols = doc.get("protocols") or []
    if not isinstance(protocols, list) or not protocols:
        raise GateError("[x] Refusing to start: scope JSON needs a non-empty protocols list (e.g. Wi-Fi, Bluetooth).")
    location = sanitize_text(doc.get("location") or "", 200)
    if not location:
        raise GateError("[x] Refusing to start: scope JSON needs a location.")
    window = doc.get("authorized_time_window") or {}
    if not isinstance(window, dict):
        raise GateError("[x] Refusing to start: authorized_time_window must be an object with start_utc and end_utc.")
    start = str(window.get("start_utc") or "").strip()
    end = str(window.get("end_utc") or "").strip()
    if not start or not end:
        raise GateError("[x] Refusing to start: authorized_time_window needs start_utc and end_utc (ISO-8601 UTC).")
    operators = doc.get("authorized_operators") or []
    if not isinstance(operators, list) or not operators:
        raise GateError("[x] Refusing to start: scope JSON needs a non-empty authorized_operators list.")
    clean_ops = []
    for op in operators:
        c = sanitize_text(op, MAX_GATE_LEN)
        if not c:
            raise GateError("[x] Refusing to start: authorized_operators contains an empty name.")
        clean_ops.append(c)
    return {
        "format": "json",
        "protocols": [sanitize_text(x, 32) for x in protocols],
        "location": location,
        "authorized_operators": clean_ops,
        "window_start_utc": start,
        "window_end_utc": end,
        "raw_sha256": hashlib.sha256(data).hexdigest(),
        "path": str(path.resolve()),
        "notes": sanitize_text(doc.get("notes") or "", 500),
    }


def _parse_iso_utc(value: str) -> Optional[datetime]:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def evaluate_scope(auth: Authorization, scope: dict[str, Any], *, now: Optional[datetime] = None) -> dict[str, Any]:
    """Compare the run against a parsed scope. Warn by default; --strict-scope refuses."""
    now = now or datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "format": scope.get("format"),
        "path": scope.get("path"),
        "sha256": scope.get("raw_sha256"),
        "protocols": scope.get("protocols") or [],
        "location": scope.get("location") or "",
        "window_start_utc": scope.get("window_start_utc") or "",
        "window_end_utc": scope.get("window_end_utc") or "",
        "authorized_operators": scope.get("authorized_operators") or [],
        "run_start_utc": utc_iso(now.timestamp()),
        "operator_authorized": None,
        "within_window": None,
        "issues": [],
    }
    if scope.get("format") != "json":
        result["issues"].append("scope file is free-form text; structured window/operator checks skipped")
        return result
    ops = [o.casefold() for o in result["authorized_operators"]]
    result["operator_authorized"] = auth.operator.casefold() in ops
    if not result["operator_authorized"]:
        result["issues"].append(
            f"operator {auth.operator!r} is not in authorized_operators"
        )
    start = _parse_iso_utc(result["window_start_utc"])
    end = _parse_iso_utc(result["window_end_utc"])
    if start is None or end is None:
        result["issues"].append("authorized_time_window timestamps are not valid ISO-8601 UTC")
        result["within_window"] = False
    else:
        if end < start:
            result["issues"].append("authorized_time_window end_utc is before start_utc")
        result["within_window"] = start <= now <= end
        if not result["within_window"]:
            result["issues"].append(
                f"run start {result['run_start_utc']} is outside "
                f"{result['window_start_utc']} .. {result['window_end_utc']}"
            )
    return result


def authorize(args: argparse.Namespace, *, stdin_isatty: Optional[bool] = None) -> Authorization:
    roe = _gate_value("--roe-id (ROE ID)", args.roe_id)
    ref = _gate_value("--auth-ref (authorization reference)", args.auth_ref)
    op = _gate_value("--operator (operator name)", args.operator)
    profile = (getattr(args, "profile", None) or "broad").strip().lower()
    if profile not in {"strict", "broad"}:
        raise GateError("[x] Refusing to start: --profile must be 'strict' or 'broad'.")
    auth = Authorization(
        roe_id=roe,
        auth_ref=ref,
        operator=op,
        allow_packet_logging_risk=bool(getattr(args, "allow_packet_logging_risk", False)),
        profile=profile,
        strict_scope=bool(getattr(args, "strict_scope", False)),
        host_clock=host_clock_state(),
    )
    if args.scope_file:
        sp = Path(args.scope_file)
        if not sp.is_file():
            raise GateError(f"[x] Refusing to start: scope file {sp} not found.")
        data = sp.read_bytes()
        if len(data) > MAX_SCOPE_BYTES:
            raise GateError("[x] Refusing to start: scope file is larger than 1 MB.")
        scope = parse_scope_document(data, sp)
        auth.scope_file = scope["path"]
        auth.scope_sha256 = scope["raw_sha256"]
        auth.scope_check = evaluate_scope(auth, scope)
        if auth.scope_check["issues"] and auth.strict_scope:
            detail = "; ".join(auth.scope_check["issues"])
            raise GateError(f"[x] Refusing to start (--strict-scope): {detail}")
    elif getattr(args, "strict_scope", False):
        raise GateError("[x] Refusing to start: --strict-scope requires --scope-file.")
    if not args.i_have_roe:
        tty = sys.stdin.isatty() if stdin_isatty is None else stdin_isatty
        if not tty:
            raise GateError("[x] Refusing to start: no TTY. Pass --i-have-roe to acknowledge written authorization.")
        print(DISCLAIMER)
        answer = input("Type YES to confirm written authorization for this survey: ").strip()
        if answer.upper() != "YES":
            raise GateError("[x] Aborted. Nothing was read.")
    auth.acknowledged_at = utc_iso()
    return auth


def banner_lines(auth: Authorization, mode: str) -> list[str]:
    lines = [
        f"{TOOL_NAME} {VERSION}  —  mode: {mode}  profile: {auth.profile}",
        f"ROE ID: {auth.roe_id}   Authorization: {auth.auth_ref}   Operator: {auth.operator}",
    ]
    if auth.scope_sha256:
        lines.append(f"Scope file: {auth.scope_file} (sha256 {auth.scope_sha256[:16]}…)")
        sc = auth.scope_check or {}
        if sc.get("within_window") is not None:
            lines.append(
                f"Scope window: {'INSIDE' if sc['within_window'] else 'OUTSIDE'} "
                f"({sc.get('window_start_utc')} .. {sc.get('window_end_utc')})"
            )
        if sc.get("operator_authorized") is not None:
            lines.append(
                f"Scope operator: {'authorized' if sc['operator_authorized'] else 'NOT in authorized_operators'}"
            )
        for issue in sc.get("issues") or []:
            lines.append(f"Scope note: {issue}")
    if auth.allow_packet_logging_risk:
        lines.append(PACKET_OVERRIDE_LINE)
    lines += [ROE_LINE, ATTESTATION_LINE, HYPOTHESIS_LINE, ATTRIBUTION_LINE, INTEGRITY_LINE]
    return lines


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

CSV_COLUMNS = [
    "statement", "confidence_basis", "confidence_note", "matched_name_rule",
    "matched_vendor_rule", "ssid", "ssid_hex", "bt_name", "bt_name_hex", "mac",
    "bssid", "vendor", "phy", "device_type", "channel", "signal_last_dbm",
    "signal_max_dbm", "rssi_samples", "signal_trend_hint", "first_seen_utc",
    "last_seen_utc",
]


def candidate_row(c: Candidate, wl: Watchlist) -> dict[str, Any]:
    return {
        "statement": CANDIDATE_WORDING[c.basis],
        "confidence_basis": c.basis,
        "confidence_note": CONFIDENCE_NOTE[c.basis],
        "matched_name_rule": c.name_label,
        "matched_vendor_rule": c.vendor_label,
        "ssid": sanitize_text(c.ssid_raw),
        "ssid_hex": raw_hex(c.ssid_raw),
        "bt_name": sanitize_text(c.btname_raw),
        "bt_name_hex": raw_hex(c.btname_raw),
        "mac": c.mac,
        "bssid": c.bssid,
        "vendor": sanitize_text(c.vendor),
        "phy": sanitize_text(c.phy, 32),
        "device_type": sanitize_text(c.dtype, 32),
        "channel": sanitize_text(c.channel, 16),
        "signal_last_dbm": c.last_dbm if c.last_dbm is not None else "",
        "signal_max_dbm": c.max_dbm if c.max_dbm is not None else "",
        "rssi_samples": len(c.samples),
        "signal_trend_hint": signal_trend(c.samples, wl),
        "first_seen_utc": utc_iso(c.first_time) if c.first_time else "",
        "last_seen_utc": utc_iso(c.last_time) if c.last_time else "",
    }


def header_block(auth: Authorization, wl: Watchlist, mode: str, source: str) -> list[str]:
    lines = [
        f"{TOOL_NAME} {VERSION}",
        f"ROE ID: {auth.roe_id}",
        f"Authorization reference: {auth.auth_ref}",
        f"Operator: {auth.operator}",
        f"Scope file: {auth.scope_file or '(none)'} sha256={auth.scope_sha256 or '-'}",
        f"Mode: {mode}  Profile: {auth.profile}  Source: {source}",
        f"Config sha256: {wl.sha256}",
        f"Overlay: {wl.overlay_source or '(none)'} sha256={wl.overlay_sha256 or '-'}",
        f"Host clock NTP synchronized: {auth.host_clock.get('ntp_synchronized', 'unknown')}",
        f"Host clock timezone: {auth.host_clock.get('timezone', 'unknown')}",
        ROE_LINE,
        ATTESTATION_LINE,
        HYPOTHESIS_LINE,
        ATTRIBUTION_LINE,
        INTEGRITY_LINE,
    ]
    if auth.allow_packet_logging_risk:
        lines.append(PACKET_OVERRIDE_LINE)
    return lines


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_outputs(
    outdir: Path,
    *,
    auth: Authorization,
    wl: Watchlist,
    tracker: Tracker,
    mode: str,
    source: str,
    started: float,
    warnings: list[str],
) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    rows = [candidate_row(c, wl) for c in sorted(tracker.candidates.values(), key=lambda c: (-(c.max_dbm or -999), c.mac))]
    head = header_block(auth, wl, mode, source)

    csv_path = outdir / "candidates.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        for line in head:
            fh.write("# " + line + "\n")
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: (csv_safe(v) if isinstance(v, str) else v) for k, v in row.items()})

    notices = [ROE_LINE, ATTESTATION_LINE, HYPOTHESIS_LINE, ATTRIBUTION_LINE, INTEGRITY_LINE]
    if auth.allow_packet_logging_risk:
        notices.append(PACKET_OVERRIDE_LINE)
    meta = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "roe_id": auth.roe_id,
        "authorization_reference": auth.auth_ref,
        "operator": auth.operator,
        "scope_file": auth.scope_file,
        "scope_sha256": auth.scope_sha256,
        "scope_check": auth.scope_check,
        "acknowledged_at_utc": auth.acknowledged_at,
        "attestation": ATTESTATION_LINE,
        "allow_packet_logging_risk": auth.allow_packet_logging_risk,
        "profile": auth.profile,
        "mode": mode,
        "source": source,
        "started_utc": utc_iso(started),
        "finished_utc": utc_iso(),
        "host_clock": auth.host_clock,
        "config_file": wl.source,
        "config_sha256": wl.sha256,
        "overlay_file": wl.overlay_source or "",
        "overlay_sha256": wl.overlay_sha256 or "",
        "notice": notices,
        "warnings": warnings,
        "devices_seen": len(tracker.devices_seen),
        "candidates": len(rows),
        "integrity_note": INTEGRITY_LINE,
    }
    json_path = outdir / "candidates.json"
    json_path.write_text(json.dumps({"header": head, "session": meta, "candidates": rows}, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    session_path = outdir / "session.json"
    session_path.write_text(json.dumps(meta, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    written = [csv_path, json_path, session_path]
    if wl.source and Path(wl.source).is_file():
        cfg_copy = outdir / "config_used.json"
        shutil.copyfile(wl.source, cfg_copy)
        written.append(cfg_copy)
    if wl.overlay_source and Path(wl.overlay_source).is_file():
        ov_copy = outdir / "overlay_used.json"
        shutil.copyfile(wl.overlay_source, ov_copy)
        written.append(ov_copy)
    sums = outdir / "SHA256SUMS"
    sums.write_text("".join(f"{sha256_file(p)}  {p.name}\n" for p in written), encoding="utf-8")
    written.append(sums)
    for p in written:
        os.chmod(p, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 0444
    return written


def render_table(
    tracker: Tracker,
    wl: Watchlist,
    auth: Authorization,
    mode: str,
    clear: bool,
    *,
    include_banner: bool = True,
) -> str:
    out: list[str] = []
    if clear:
        out.append("\033[2J\033[H")
    if include_banner:
        out += banner_lines(auth, mode)
    out.append(f"Devices seen: {len(tracker.devices_seen)}   Candidates: {len(tracker.candidates)}   {utc_iso()}")
    out.append("")
    hdr = f"{'BASIS':<9} {'SSID / BT NAME':<24} {'MAC':<17} {'VENDOR':<18} {'CH':>4} {'dBm':>5} {'TREND (hint)':<14} LAST SEEN (UTC)"
    out.append(hdr)
    out.append("-" * len(hdr))
    cands = sorted(tracker.candidates.values(), key=lambda c: (-(c.last_dbm or -999), c.mac))
    for c in cands:
        name = sanitize_text(c.ssid_raw or c.btname_raw, 24) or "—"
        vendor = sanitize_text(c.vendor or "Unknown", 18)
        dbm = f"{c.last_dbm:.0f}" if c.last_dbm is not None else "—"
        trend = signal_trend(c.samples, wl).split(" ")[0]
        last = utc_iso(c.last_time)[11:] if c.last_time else "—"
        out.append(f"{c.basis:<9} {name:<24} {c.mac:<17} {vendor:<18} {sanitize_text(c.channel, 4):>4} {dbm:>5} {trend:<14} {last}")
    if not cands:
        out.append("(no candidates yet)")
    out.append("")
    out.append("Each row: " + CANDIDATE_WORDING["name"] + " (or vendor/BT variant). Confidence: name/oui = low, name+oui = medium.")
    return "\n".join(out)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def app_dir() -> Path:
    return Path(__file__).resolve().parent


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nightwatchman.py",
        description=f"{TOOL_NAME}: passive Kismet watcher for camera/dash cam candidates (authorized use only).",
    )
    g = p.add_argument_group("authorization (all three required)")
    g.add_argument("--roe-id", help="Rules of Engagement ID")
    g.add_argument("--auth-ref", help="Authorization reference (letter, ticket, or approval number)")
    g.add_argument("--operator", help="Operator name")
    g.add_argument("--scope-file", help="Optional scope document (JSON template preferred); SHA-256 recorded")
    g.add_argument("--strict-scope", action="store_true",
                   help="Refuse to start if the run is outside the scope window or the operator is not listed")
    g.add_argument("--i-have-roe", action="store_true", help="Acknowledge written authorization without the YES prompt")
    g.add_argument("--allow-packet-logging-risk", action="store_true",
                   help="Override: allow start when Kismet pcap/packet logging is on or unverifiable (recorded)")
    g.add_argument("--profile", choices=("strict", "broad"), default="broad",
                   help="strict = brand names + vendor only; broad = full watchlist including generic IPC/CAM/DVR (default)")
    s = p.add_argument_group("source (pick one; default is live Kismet)")
    s.add_argument("--kismet-url", default=os.environ.get("KISMET_URL", DEFAULT_KISMET_URL), help=f"Kismet REST base URL (default {DEFAULT_KISMET_URL})")
    s.add_argument("--kismetdb", help="Read a finished .kismet log (read-only) instead of a live server")
    s.add_argument("--demo", action="store_true", help="Use the bundled fixture; no Kismet, no radio")
    s.add_argument("--fixture", default=None, help="Fixture file for --demo")
    p.add_argument("--config", default=None, help=f"Watchlist JSON (default {DEFAULT_CONFIG} next to the script)")
    p.add_argument(
        "--watchlist-extra",
        default=None,
        help="Optional overlay JSON merged onto the base watchlist "
             "(default: nightwatchman.local.json next to the base file if present)",
    )
    p.add_argument("--ieee-csv", default=None, help="Optional prefix,vendor CSV for MACs Kismet left unnamed")
    p.add_argument("--interval", type=float, default=5.0, help="Seconds between live polls (default 5)")
    p.add_argument("--duration", type=float, default=0.0, help="Stop after N seconds (0 = until Ctrl-C)")
    p.add_argument("-o", "--output", default=None, help="Output directory (default ./nightwatchman_<UTC>/)")
    p.add_argument("--no-clear", action="store_true", help="Do not redraw the screen between polls")
    p.add_argument("--self-test", action="store_true", help="Run the offline unit tests and exit")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {VERSION}")
    return p


def run_self_test() -> int:
    import unittest

    suite = unittest.defaultTestLoader.discover(str(app_dir() / "tests"), top_level_dir=str(app_dir()))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv: Optional[list[str]] = None) -> int:
    if sys.version_info < MIN_PYTHON:
        log(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required.", "err")
        return 2
    args = build_parser().parse_args(argv)
    if args.self_test:
        return run_self_test()
    if args.demo and args.kismetdb:
        log("Pick one of --demo and --kismetdb.", "err")
        return 2
    if not math.isfinite(args.interval) or args.interval <= 0:
        log("--interval must be a positive finite number of seconds.", "err")
        return 2
    if not math.isfinite(args.duration) or args.duration < 0:
        log("--duration must be zero or a positive finite number of seconds.", "err")
        return 2

    try:
        auth = authorize(args)
    except GateError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    cfg_path = Path(args.config) if args.config else app_dir() / DEFAULT_CONFIG
    extra = Path(args.watchlist_extra) if args.watchlist_extra else None
    try:
        wl = apply_profile(load_watchlist(cfg_path, overlay=extra), auth.profile)
    except ConfigError as exc:
        log(f"Config rejected: {exc}", "err")
        return 2
    ieee = load_ieee_table(Path(args.ieee_csv) if args.ieee_csv else app_dir() / "ieee_mac_vendors.csv")

    started = time.time()
    outdir = Path(args.output) if args.output else Path.cwd() / f"{TOOL_ID}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    if outdir.exists() and any(outdir.iterdir()):
        log(f"Output directory {outdir} is not empty; refusing to overwrite evidence.", "err")
        return 2

    tracker = Tracker(wl, ieee)
    warnings: list[str] = []
    clear = sys.stdout.isatty() and not args.no_clear
    mode = "demo" if args.demo else ("kismetdb" if args.kismetdb else "live")
    banner_printed = False

    def emit_banner() -> None:
        nonlocal banner_printed
        if banner_printed:
            return
        for line in banner_lines(auth, mode):
            log(line)
        for issue in (auth.scope_check or {}).get("issues") or []:
            log(f"Scope: {issue}", "warn")
        banner_printed = True

    try:
        if args.demo:
            fixture = Path(args.fixture) if args.fixture else app_dir() / DEMO_FIXTURE
            data = json.loads(fixture.read_text(encoding="utf-8"))
            source = f"fixture {fixture.name}"
            risks = packet_logging_warnings_from_active(data.get("logging_active", []))
            notices = enforce_packet_logging_gate(risks, auth.allow_packet_logging_risk)
            warnings += notices
            emit_banner()
            for w in notices:
                log(w, "warn")
            base = started
            for i, poll in enumerate(data.get("polls", [])):
                for dev in poll:
                    obs = parse_device(dev)
                    if obs:
                        if obs.last_time is not None and obs.last_time < 10_000:
                            obs.last_time = base + obs.last_time  # fixture uses offsets
                            obs.first_time = base + (obs.first_time or 0)
                        tracker.ingest(obs, base + i)
            # Demo: banner already emitted once via emit_banner().
            print(render_table(tracker, wl, auth, mode, clear=False, include_banner=False))
        elif args.kismetdb:
            path = Path(args.kismetdb)
            source = f"kismetdb {path.name} sha256={sha256_file(path)}"
            risks = kismetdb_risks(path)
            notices = enforce_packet_logging_gate(risks, auth.allow_packet_logging_risk)
            warnings += notices
            emit_banner()
            for msg in notices:
                log(msg, "warn")
            for dev in read_kismetdb_devices(path):
                obs = parse_device(dev)
                if obs:
                    tracker.ingest(obs, started)
            print(render_table(tracker, wl, auth, mode, clear=False, include_banner=False))
        else:
            client = KismetClient.from_env(args.kismet_url)
            source = f"kismet {client.describe()}"
            client.get_json("/system/status.json")
            risks = check_kismet_logging(client)
            notices = enforce_packet_logging_gate(risks, auth.allow_packet_logging_risk)
            warnings += notices
            emit_banner()
            for msg in notices:
                log(msg, "warn")
            live = LiveSource(client, started)
            deadline = started + args.duration if args.duration else None
            try:
                while True:
                    now = time.time()
                    for dev in live.poll():
                        obs = parse_device(dev)
                        if obs:
                            tracker.ingest(obs, now)
                    print(
                        render_table(
                            tracker, wl, auth, mode, clear=clear,
                            include_banner=clear or not banner_printed,
                        ),
                        flush=True,
                    )
                    banner_printed = True
                    if deadline and time.time() >= deadline:
                        break
                    time.sleep(args.interval)
            except KeyboardInterrupt:
                log("Stopped by operator; writing reports.")
    except PacketLoggingRisk as exc:
        emit_banner()
        for reason in exc.reasons:
            log(reason, "err")
        log(
            "Refusing to start: packet/pcap logging present or unverifiable. "
            "Disable it, or pass --allow-packet-logging-risk (recorded in every output).",
            "err",
        )
        return 2
    except (KismetError, OSError, json.JSONDecodeError) as exc:
        emit_banner()
        log(f"Stopped: {sanitize_text(exc, 200)}", "err")
        if not tracker.devices_seen:
            return 1
        source = locals().get("source", mode)

    written = write_outputs(
        outdir, auth=auth, wl=wl, tracker=tracker, mode=mode,
        source=source, started=started, warnings=warnings,
    )
    log(f"Wrote {len(written)} read-only files to {outdir}", "ok")
    log(INTEGRITY_LINE)
    for p in written:
        log(f"  {p.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

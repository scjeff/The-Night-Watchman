# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline tests for The Night Watchman. No radio, no real Kismet: a mock
Kismet REST server runs on 127.0.0.1 inside the test process."""

from __future__ import annotations

import argparse
import base64
import contextlib
import csv
import hashlib
import io
import json
import os
import sqlite3
import stat
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import nightwatchman as nw  # noqa: E402

FAKE_USER = "nwtestuser"
FAKE_PASS = "nw-fake-secret-7f3a"  # test-only; asserted never to appear in output
GATE = [
    "--roe-id", "ROE-T-1", "--auth-ref", "AUTH-T-2",
    "--operator", "Test Operator", "--i-have-roe",
]


def wl_default() -> nw.Watchlist:
    return nw.load_watchlist(ROOT / "nightwatchman.json")


def run_main(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = nw.main(argv)
    return rc, out.getvalue(), err.getvalue()


def write_scope(td: Path, **overrides) -> Path:
    doc = {
        "protocols": ["Wi-Fi", "Bluetooth"],
        "location": "Lab bay 3",
        "authorized_time_window": {
            "start_utc": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end_utc": (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "authorized_operators": ["Test Operator", "Jane Doe"],
        "notes": "unit test scope",
    }
    for k, v in overrides.items():
        if k == "authorized_time_window" and isinstance(v, dict):
            doc["authorized_time_window"].update(v)
        else:
            doc[k] = v
    path = td / "scope.json"
    path.write_text(json.dumps(doc, indent=2))
    return path


class SanitizeTests(unittest.TestCase):
    def test_strips_controls_ansi_bidi(self):
        raw = "cam\x1b[31mred\x00\x07\u202eevil\u200b\x9b2J"
        self.assertEqual(nw.sanitize_text(raw), "camredevil")

    def test_truncates(self):
        self.assertEqual(len(nw.sanitize_text("A" * 500)), nw.MAX_DISPLAY_LEN)

    def test_csv_formula_guard(self):
        for lead in ("=", "+", "-", "@", "\t", "|", "%"):
            self.assertTrue(nw.csv_safe(lead + "cmd").startswith("'"))
        self.assertEqual(nw.csv_safe("WOLFBOX_1"), "WOLFBOX_1")

    def test_raw_hex_preserves_bytes(self):
        self.assertEqual(nw.raw_hex("a\x1b"), "611b")


class ConfigTests(unittest.TestCase):
    def test_default_config_loads_and_has_wolfbox(self):
        wl = wl_default()
        self.assertTrue(any("Wolfbox" in p.label for p in wl.ssid))
        self.assertEqual(len(wl.sha256), 64)

    def _bad(self, pattern):
        with self.assertRaises(nw.ConfigError):
            nw.parse_watchlist({"ssid_patterns": [{"label": "x", "pattern": pattern}]})

    def test_rejects_invalid_regex(self):
        self._bad("(unclosed")

    def test_rejects_nested_quantifier(self):
        self._bad("(a+)+$")
        self._bad(r"(\w*)*x")

    def test_rejects_empty_match(self):
        self._bad("x*")

    def test_rejects_backreference(self):
        self._bad(r"(a)\1")

    def test_rejects_too_long(self):
        self._bad("a" * (nw.MAX_PATTERN_LEN + 1))

    def test_rejects_bad_shapes(self):
        with self.assertRaises(nw.ConfigError):
            nw.parse_watchlist({"ssid_patterns": "cam"})
        with self.assertRaises(nw.ConfigError):
            nw.parse_watchlist({"ssid_patterns": [], "vendor_patterns": []})
        with self.assertRaises(nw.ConfigError):
            nw.parse_watchlist({"oui_prefixes": [{"prefix": "AB", "label": "x"}]})

    def test_strict_profile_drops_generics(self):
        broad = wl_default()
        strict = nw.apply_profile(broad, "strict")
        self.assertTrue(any(p.label == "Wolfbox dash cam" for p in strict.ssid))
        self.assertFalse(any("Generic" in p.label for p in strict.ssid))
        self.assertEqual(len(strict.vendor), len(broad.vendor))
        self.assertEqual(strict.model, [])

    def test_overlay_merge_appends_model_patterns(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td, "base.json")
            over = Path(td, "extra.json")
            base.write_text(json.dumps({
                "ssid_patterns": [{"label": "Wolfbox dash cam", "pattern": "wolf\\s*box"}],
                "vendor_patterns": [],
            }))
            over.write_text(json.dumps({
                "model_patterns": [
                    {"label": "Wolfbox listing model MODEL123 (unverified as SSID)", "pattern": "model123"},
                ],
            }))
            # Do not auto-pick a sibling local file: pass overlay explicitly.
            wl = nw.load_watchlist(base, overlay=over)
            self.assertEqual(len(wl.ssid), 1)
            self.assertEqual(len(wl.model), 1)
            self.assertTrue(wl.overlay_sha256)
            self.assertIn("extra.json", wl.overlay_source)

    def test_overlay_invalid_pattern_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td, "base.json")
            over = Path(td, "extra.json")
            base.write_text(json.dumps({
                "ssid_patterns": [{"label": "Wolfbox dash cam", "pattern": "wolf\\s*box"}],
            }))
            over.write_text(json.dumps({
                "model_patterns": [{"label": "bad", "pattern": "(a+)+"}],
            }))
            with self.assertRaises(nw.ConfigError):
                nw.load_watchlist(base, overlay=over)

    def test_autoload_local_overlay_next_to_base(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td, "nightwatchman.json")
            local = Path(td, "nightwatchman.local.json")
            base.write_text(json.dumps({
                "ssid_patterns": [{"label": "Wolfbox dash cam", "pattern": "wolf\\s*box"}],
            }))
            local.write_text(json.dumps({
                "model_patterns": [{"label": "Wolfbox listing model MODEL123 (unverified as SSID)", "pattern": "model123"}],
            }))
            wl = nw.load_watchlist(base)  # auto
            self.assertEqual(len(wl.model), 1)


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.wl = wl_default()

    def obs(self, **kw):
        base = dict(
            mac="00:11:22:33:44:55", phy="IEEE802.11", dtype="Wi-Fi AP",
            ssid_raw="", btname_raw="", bssid="", vendor="", channel="6",
            signal_dbm=-60.0, first_time=1.0, last_time=2.0,
        )
        base.update(kw)
        return nw.Observation(**base)

    def test_name_only(self):
        hit = nw.classify(self.obs(ssid_raw="WOLFBOX_MODEL123"), self.wl, {})
        self.assertEqual(hit[0], "name")
        self.assertIn("Wolfbox", hit[1])

    def test_oui_only(self):
        hit = nw.classify(self.obs(vendor="Hangzhou Hikvision Digital Technology"), self.wl, {})
        self.assertEqual(hit[0], "oui")

    def test_both(self):
        hit = nw.classify(self.obs(ssid_raw="IPC-01", vendor="Zhejiang Dahua Technology"), self.wl, {})
        self.assertEqual(hit[0], "name+oui")

    def test_bt_name(self):
        hit = nw.classify(self.obs(phy="BTLE", btname_raw="VIOFO A229"), self.wl, {})
        self.assertEqual(hit[0], "bt_name")

    def test_no_match(self):
        self.assertIsNone(nw.classify(self.obs(ssid_raw="HomeNet-5G", vendor="Netgear"), self.wl, {}))
        self.assertIsNone(nw.classify(self.obs(ssid_raw="Camden Library"), self.wl, {}))

    def test_ieee_fallback_skips_local_mac(self):
        ieee = {"021A11": "Hikvision"}
        self.assertIsNone(nw.classify(self.obs(mac="02:1A:11:00:00:01", vendor="Unknown"), self.wl, ieee))
        ieee = {"BCAD28": "Hangzhou Hikvision"}
        self.assertEqual(nw.classify(self.obs(mac="BC:AD:28:00:00:01", vendor="Unknown"), self.wl, ieee)[0], "oui")

    def test_wording_never_asserts_camera(self):
        for basis, text in nw.CANDIDATE_WORDING.items():
            self.assertTrue(text.startswith("candidate:"))
            self.assertNotIn("this is a camera", text.lower())
            self.assertIn(basis, nw.CONFIDENCE_NOTE)

    def test_wolfbox_brand_label_on_ssid(self):
        hit = nw.classify(self.obs(ssid_raw="WOLFBOX_MODEL123"), self.wl, {})
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0], "name")
        self.assertEqual(hit[1], "Wolfbox dash cam")

    def test_model_only_low_confidence(self):
        # Build a watchlist with brand + model, then match a model-only string.
        data = {
            "ssid_patterns": [{"label": "Wolfbox dash cam", "pattern": "wolf\\s*box"}],
            "model_patterns": [
                {"label": "Wolfbox listing model MODEL123 (unverified as SSID)", "pattern": "model123"},
            ],
        }
        wl = nw.parse_watchlist(data)
        hit = nw.classify(self.obs(ssid_raw="UNIT_MODEL123_CAM"), wl, {})
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0], "model")
        self.assertIn("MODEL123", hit[1])
        self.assertIn("unverified", nw.CONFIDENCE_NOTE["model"].lower())

    def test_brand_preferred_over_model_on_same_ssid(self):
        data = {
            "ssid_patterns": [{"label": "Wolfbox dash cam", "pattern": "wolf\\s*box"}],
            "model_patterns": [
                {"label": "Wolfbox listing model MODEL123 (unverified as SSID)", "pattern": "model123"},
            ],
        }
        wl = nw.parse_watchlist(data)
        hit = nw.classify(self.obs(ssid_raw="WOLFBOX_MODEL123"), wl, {})
        self.assertEqual(hit[0], "name")
        self.assertEqual(hit[1], "Wolfbox dash cam")


class TrackerMergeTests(unittest.TestCase):
    def setUp(self):
        self.wl = wl_default()
        self.tr = nw.Tracker(self.wl, {})

    def obs(self, **kw):
        base = dict(
            mac="BC:AD:28:00:00:99", phy="IEEE802.11", dtype="Wi-Fi AP",
            ssid_raw="", btname_raw="", bssid="BC:AD:28:00:00:99", vendor="",
            channel="11", signal_dbm=-55.0, first_time=1.0, last_time=2.0,
        )
        base.update(kw)
        return nw.Observation(**base)

    def test_oui_then_name_without_vendor_becomes_name_plus_oui(self):
        # Repro: Hikvision OUI-only (no SSID), then SSID IPC-Lobby with vendor="".
        self.tr.ingest(self.obs(vendor="Hangzhou Hikvision Digital Technology Co.,Ltd.", ssid_raw=""), 1.0)
        cand = self.tr.candidates["BC:AD:28:00:00:99"]
        self.assertEqual(cand.basis, "oui")
        self.assertEqual(cand.vendor_label, "Hikvision")
        self.tr.ingest(self.obs(vendor="", ssid_raw="IPC-Lobby"), 2.0)
        cand = self.tr.candidates["BC:AD:28:00:00:99"]
        self.assertEqual(cand.basis, "name+oui")
        self.assertEqual(cand.vendor_label, "Hikvision")
        self.assertIn("IP", cand.name_label)

    def test_name_then_oui_becomes_name_plus_oui(self):
        self.tr.ingest(self.obs(vendor="", ssid_raw="IPC-Lobby"), 1.0)
        self.assertEqual(self.tr.candidates["BC:AD:28:00:00:99"].basis, "name")
        self.tr.ingest(self.obs(vendor="Hangzhou Hikvision Digital Technology Co.,Ltd.", ssid_raw=""), 2.0)
        cand = self.tr.candidates["BC:AD:28:00:00:99"]
        self.assertEqual(cand.basis, "name+oui")
        self.assertEqual(cand.vendor_label, "Hikvision")


    def test_model_label_upgrades_to_brand(self):
        data = {
            "ssid_patterns": [{"label": "Wolfbox dash cam", "pattern": "wolf\\s*box"}],
            "model_patterns": [
                {"label": "Wolfbox listing model MODEL123 (unverified as SSID)", "pattern": "model123"},
            ],
        }
        tr = nw.Tracker(nw.parse_watchlist(data), {})
        tr.ingest(self.obs(ssid_raw="MODEL123_only", vendor="Unknown"), 1.0)
        self.assertEqual(tr.candidates["BC:AD:28:00:00:99"].basis, "model")
        tr.ingest(self.obs(ssid_raw="WOLFBOX_MODEL123", vendor="Unknown"), 2.0)
        cand = tr.candidates["BC:AD:28:00:00:99"]
        self.assertEqual(cand.name_label, "Wolfbox dash cam")
        self.assertEqual(cand.basis, "name")

    def test_generic_name_upgrades_to_brand_label(self):
        # Cam-Lobby (Generic camera) then WOLFBOX_MODEL123 must end as Wolfbox.
        self.tr.ingest(self.obs(ssid_raw="Cam-Lobby", vendor="Unknown"), 1.0)
        cand = self.tr.candidates["BC:AD:28:00:00:99"]
        self.assertEqual(cand.basis, "name")
        self.assertIn("Generic", cand.name_label)
        self.tr.ingest(self.obs(ssid_raw="WOLFBOX_MODEL123", vendor="Unknown"), 2.0)
        cand = self.tr.candidates["BC:AD:28:00:00:99"]
        self.assertEqual(cand.name_label, "Wolfbox dash cam")
        self.assertEqual(cand.basis, "name")

    def test_brand_name_not_downgraded_to_generic(self):
        self.tr.ingest(self.obs(ssid_raw="WOLFBOX_MODEL123", vendor="Unknown"), 1.0)
        self.tr.ingest(self.obs(ssid_raw="Cam-Lobby", vendor="Unknown"), 2.0)
        cand = self.tr.candidates["BC:AD:28:00:00:99"]
        self.assertEqual(cand.name_label, "Wolfbox dash cam")

    def test_sticky_candidate_when_ssid_later_benign(self):
        self.tr.ingest(self.obs(ssid_raw="WOLFBOX_1", vendor="Unknown"), 1.0)
        self.assertIn("BC:AD:28:00:00:99", self.tr.candidates)
        self.tr.ingest(self.obs(ssid_raw="HomeNet", vendor="Unknown"), 2.0)
        cand = self.tr.candidates["BC:AD:28:00:00:99"]
        self.assertEqual(cand.basis, "name")
        self.assertIn("Wolfbox", cand.name_label)


class TrendTests(unittest.TestCase):
    def setUp(self):
        self.wl = wl_default()

    def test_trend(self):
        self.assertEqual(nw.signal_trend([(0, -50)], self.wl), "insufficient samples")
        self.assertTrue(nw.signal_trend([(i, -50 - (i % 2)) for i in range(6)], self.wl).startswith("steady"))
        self.assertTrue(nw.signal_trend([(i, -80 + 5 * i) for i in range(6)], self.wl).startswith("varying"))


class ParseDeviceTests(unittest.TestCase):
    def test_full_nested_json(self):
        dev = {
            "kismet.device.base.macaddr": "aa:bb:cc:00:00:01",
            "kismet.device.base.phyname": "IEEE802.11",
            "kismet.device.base.type": "Wi-Fi AP",
            "kismet.device.base.channel": "11",
            "kismet.device.base.manuf": "Wyze Labs Inc",
            "kismet.device.base.first_time": 100,
            "kismet.device.base.last_time": 200,
            "kismet.device.base.signal": {"kismet.common.signal.last_signal": -58},
            "dot11.device": {
                "dot11.device.last_beaconed_ssid_record": {"dot11.advertisedssid.ssid": "WYZE_CAM_V3"},
                "dot11.device.last_bssid": "AA:BB:CC:00:00:01",
            },
        }
        obs = nw.parse_device(dev)
        self.assertEqual(obs.mac, "AA:BB:CC:00:00:01")
        self.assertEqual(obs.ssid_raw, "WYZE_CAM_V3")
        self.assertEqual(obs.signal_dbm, -58)

    def test_basic_field_ssid_fallback_from_commonname(self):
        # Shape after Kismet rejects dot11 fields: aliased base fields only.
        dev = {
            "mac": "AA:BB:CC:00:00:0B",
            "phy": "IEEE802.11",
            "type": "Wi-Fi AP",
            "channel": "6",
            "manuf": "Unknown",
            "commonname": "WOLFBOX_MODEL123_FALLBACK",
            "name": "AA:BB:CC:00:00:0B",
            "signal": -62,
            "first_time": 1,
            "last_time": 2,
        }
        obs = nw.parse_device(dev)
        self.assertEqual(obs.ssid_raw, "WOLFBOX_MODEL123_FALLBACK")
        hit = nw.classify(obs, wl_default(), {})
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0], "name")

    def test_basic_field_skips_mac_as_ssid(self):
        dev = {
            "mac": "AA:BB:CC:00:00:0C", "phy": "IEEE802.11", "type": "Wi-Fi AP",
            "commonname": "AA:BB:CC:00:00:0C", "name": "aa:bb:cc:00:00:0c", "signal": -60,
        }
        self.assertEqual(nw.parse_device(dev).ssid_raw, "")

    def test_zero_signal_is_no_sample(self):
        obs = nw.parse_device({"mac": "AA:BB:CC:00:00:01", "signal": 0})
        self.assertIsNone(obs.signal_dbm)

    def test_numeric_ssid_zero_is_not_a_name(self):
        # Kismet 2026 field views return ssid: 0 when the device has no SSID.
        obs = nw.parse_device({
            "mac": "AA:BB:CC:00:00:01",
            "phy": "IEEE802.11",
            "ssid": 0,
            "commonname": "AA:BB:CC:00:00:01",
            "signal": -40,
        })
        self.assertEqual(obs.ssid_raw, "")

    def test_numeric_ssid_falls_back_to_commonname(self):
        obs = nw.parse_device({
            "mac": "AA:BB:CC:00:00:01",
            "phy": "IEEE802.11",
            "type": "Wi-Fi AP",
            "ssid": 0,
            "commonname": "WOLFBOX_MODEL123",
            "signal": -40,
        })
        self.assertEqual(obs.ssid_raw, "WOLFBOX_MODEL123")
        hit = nw.classify(obs, wl_default(), {})
        self.assertEqual(hit[0], "name")
        self.assertEqual(hit[1], "Wolfbox dash cam")

    def test_bluetooth_device_name_when_commonname_is_mac(self):
        dev = {
            "kismet.device.base.macaddr": "AA:BB:CC:00:00:0D",
            "kismet.device.base.phyname": "Bluetooth",
            "kismet.device.base.commonname": "AA:BB:CC:00:00:0D",
            "kismet.device.base.name": "AA:BB:CC:00:00:0D",
            "bluetooth.device": {"bluetooth.device.device_name": "VIOFO A119"},
        }
        obs = nw.parse_device(dev)
        self.assertEqual(obs.btname_raw, "VIOFO A119")
        self.assertEqual(obs.ssid_raw, "")
        self.assertEqual(nw.classify(obs, wl_default(), {})[0], "bt_name")

    def test_advertised_ssid_map_list_ignores_probes(self):
        dev = {
            "kismet.device.base.macaddr": "AA:BB:CC:00:00:0E",
            "kismet.device.base.phyname": "IEEE802.11",
            "kismet.device.base.type": "Wi-Fi AP",
            "dot11.device": {
                "dot11.device.last_beaconed_ssid_record": {"dot11.advertisedssid.ssid": 0},
                "dot11.device.advertised_ssid_map": [
                    {"dot11.advertisedssid.ssid": "70mai_D08"},
                ],
                "dot11.device.probed_ssid_map": [
                    {"dot11.probedssid.ssid": "WOLFBOX_SHOULD_NOT_MATCH"},
                ],
            },
        }
        obs = nw.parse_device(dev)
        self.assertEqual(obs.ssid_raw, "70mai_D08")
        self.assertNotIn("WOLFBOX", obs.ssid_raw)
        self.assertEqual(nw.classify(obs, wl_default(), {})[1], "70mai dash cam")

    def test_bad_mac_dropped(self):
        self.assertIsNone(nw.parse_device({"mac": "nope"}))
        self.assertIsNone(nw.parse_device("not a dict"))


class PcapDetectTests(unittest.TestCase):
    def test_type_fields(self):
        for t in ("pcapng", "pcapppi", "pcap"):
            self.assertTrue(nw.entry_is_pcap_log({"kismet.logfile.type": t}))
            self.assertTrue(nw.entry_is_pcap_log({"log_type": t}))

    def test_path_suffix(self):
        self.assertTrue(nw.entry_is_pcap_log({"kismet.logfile.type": "other", "kismet.logfile.path": "/tmp/x.pcapng"}))
        self.assertTrue(nw.entry_is_pcap_log({"path": "/tmp/x.pcap"}))

    def test_no_false_positive_on_disabled_text(self):
        self.assertFalse(nw.entry_is_pcap_log({
            "kismet.logfile.type": "kismetdb",
            "kismet.logfile.path": "/tmp/note.txt",
            "note": "pcap disabled by site policy",
        }))
        self.assertEqual(nw.packet_logging_warnings_from_active([
            {"kismet.logfile.type": "kismetdb", "note": "pcap disabled"},
        ]), [])

    def test_kismet_2026_nested_type_driver_is_not_pcap(self):
        # 2026.10 puts the type under kismet.log.type_driver. The description
        # mentions packets even when the log is metadata-only.
        entry = {
            "kismet.log.type_driver": {
                "kismet.logfile.type.class": "kismet",
                "kismet.logfile.type.name": "Kismet Unified Log",
                "kismet.logfile.type.description": (
                    "Unified Kismet log containing device, data source, packet, "
                    "alert, and other runtime data"
                ),
            },
            "kismet.logfile.path": "/tmp/nwlab-20261027-18-37-17-1.kismet",
        }
        self.assertFalse(nw.entry_is_pcap_log(entry))
        self.assertEqual(nw.packet_logging_warnings_from_active([entry]), [])

    def test_kismet_2026_nested_pcapng_class(self):
        entry = {
            "kismet.log.type_driver": {"kismet.logfile.type.class": "pcapng"},
            "kismet.logfile.path": "/tmp/capture.log",
        }
        self.assertTrue(nw.entry_is_pcap_log(entry))


class GateTests(unittest.TestCase):
    def ns(self, **kw):
        base = dict(
            roe_id="R", auth_ref="A", operator="O", scope_file=None,
            i_have_roe=True, allow_packet_logging_risk=False, profile="broad",
            strict_scope=False,
        )
        base.update(kw)
        return argparse.Namespace(**base)

    def test_gate_error_is_exception_not_systemexit(self):
        self.assertTrue(issubclass(nw.GateError, Exception))
        self.assertFalse(issubclass(nw.GateError, SystemExit))

    def test_each_input_required(self):
        for key in ("roe_id", "auth_ref", "operator"):
            with self.assertRaises(nw.GateError):
                nw.authorize(self.ns(**{key: ""}))

    def test_control_chars_refused(self):
        with self.assertRaises(nw.GateError):
            nw.authorize(self.ns(operator="Jane\x1b[2J"))

    def test_no_tty_without_ack_refuses(self):
        with self.assertRaises(nw.GateError):
            nw.authorize(self.ns(i_have_roe=False), stdin_isatty=False)

    def test_scope_file_json(self):
        with tempfile.TemporaryDirectory() as td:
            sp = write_scope(Path(td))
            auth = nw.authorize(self.ns(scope_file=str(sp), operator="Test Operator"))
            self.assertEqual(auth.scope_sha256, hashlib.sha256(sp.read_bytes()).hexdigest())
            self.assertTrue(auth.scope_check["within_window"])
            self.assertTrue(auth.scope_check["operator_authorized"])
            self.assertIn("attestation", nw.ATTESTATION_LINE.lower() or "x")

    def test_scope_outside_window_warns_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            sp = write_scope(
                Path(td),
                authorized_time_window={
                    "start_utc": "2020-01-01T00:00:00Z",
                    "end_utc": "2020-01-01T01:00:00Z",
                },
            )
            auth = nw.authorize(self.ns(scope_file=str(sp), operator="Test Operator"))
            self.assertFalse(auth.scope_check["within_window"])
            self.assertTrue(any("outside" in i for i in auth.scope_check["issues"]))

    def test_strict_scope_refuses_outside_window(self):
        with tempfile.TemporaryDirectory() as td:
            sp = write_scope(
                Path(td),
                authorized_time_window={
                    "start_utc": "2020-01-01T00:00:00Z",
                    "end_utc": "2020-01-01T01:00:00Z",
                },
            )
            with self.assertRaises(nw.GateError) as cm:
                nw.authorize(self.ns(scope_file=str(sp), operator="Test Operator", strict_scope=True))
            self.assertIn("strict-scope", str(cm.exception).lower())

    def test_strict_scope_refuses_unknown_operator(self):
        with tempfile.TemporaryDirectory() as td:
            sp = write_scope(Path(td), authorized_operators=["Someone Else"])
            with self.assertRaises(nw.GateError):
                nw.authorize(self.ns(scope_file=str(sp), operator="Test Operator", strict_scope=True))

    def test_strict_scope_requires_scope_file(self):
        with self.assertRaises(nw.GateError):
            nw.authorize(self.ns(strict_scope=True))

    def test_main_refuses_without_gate(self):
        with tempfile.TemporaryDirectory() as td:
            rc, _, err = run_main(["--demo", "-o", td + "/o", "--i-have-roe", "--roe-id", "R"])
            self.assertEqual(rc, 2)
            self.assertIn("Refusing to start", err)
            self.assertFalse(Path(td, "o").exists())


def verify_outputs(test: unittest.TestCase, outdir: Path, *, expect_override: bool = False) -> dict:
    files = sorted(p.name for p in outdir.iterdir())
    expected = {"SHA256SUMS", "candidates.csv", "candidates.json", "config_used.json", "session.json"}
    # overlay_used.json appears only when a local overlay was loaded
    test.assertTrue(expected.issubset(set(files)), files)
    test.assertTrue(set(files) <= expected | {"overlay_used.json"}, files)
    for p in outdir.iterdir():
        test.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o444, p.name)
    for line in (outdir / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        test.assertEqual(hashlib.sha256((outdir / name).read_bytes()).hexdigest(), digest)
    session = json.loads((outdir / "session.json").read_text())
    test.assertEqual(session["roe_id"], "ROE-T-1")
    test.assertEqual(session["authorization_reference"], "AUTH-T-2")
    test.assertEqual(session["operator"], "Test Operator")
    test.assertEqual(session["version"], nw.VERSION)
    test.assertIn("attestation", session)
    test.assertIn("does not verify the ROE", session["attestation"])
    test.assertIn("host_clock", session)
    test.assertIn("ntp_synchronized", session["host_clock"])
    test.assertIn("integrity_note", session)
    test.assertIn("NOT tamper-proof", session["integrity_note"])
    test.assertEqual(session["allow_packet_logging_risk"], expect_override)
    test.assertEqual(session["config_sha256"], hashlib.sha256((outdir / "config_used.json").read_bytes()).hexdigest())
    head = (outdir / "candidates.csv").read_text().splitlines()[:20]
    joined = "\n".join(head)
    for needle in (
        "ROE ID: ROE-T-1", "Authorization reference: AUTH-T-2", "Operator: Test Operator",
        "written authorization / rules of engagement", "site security or the investigating party",
        "HYPOTHESIS, NOT A FINDING", "does not verify the ROE", "NOT tamper-proof",
    ):
        test.assertIn(needle, joined)
    if expect_override:
        test.assertIn("OPERATOR OVERRIDE", joined)
        test.assertTrue(any("OPERATOR OVERRIDE" in w for w in session["warnings"]))
    return session


class DemoEndToEnd(unittest.TestCase):
    def test_demo_run(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "run")
            rc, stdout, stderr = run_main(["--demo", "-o", str(out)] + GATE)
            self.assertEqual(rc, 0, stderr)
            # Banner once via emit_banner() (log -> stdout); table omits a second banner.
            self.assertEqual(stdout.count("mode: demo"), 1)
            self.assertEqual((stdout + stderr).count("mode: demo"), 1)
            self.assertIn("ROE ID: ROE-T-1", stdout)
            self.assertIn("does not verify the ROE", stdout)
            self.assertIn("NOT tamper-proof", stdout)
            self.assertNotIn("\x1b", stdout)
            session = verify_outputs(self, out)
            self.assertEqual(session["candidates"], 5)
            self.assertEqual(session["profile"], "broad")
            rows = list(csv.DictReader(
                l for l in (out / "candidates.csv").read_text().splitlines() if not l.startswith("#")
            ))
            by_mac = {r["mac"]: r for r in rows}
            self.assertEqual(by_mac["02:1A:11:00:00:01"]["confidence_basis"], "name")
            self.assertTrue(by_mac["02:1A:11:00:00:01"]["signal_trend_hint"].startswith("varying"))
            self.assertEqual(by_mac["BC:AD:28:00:00:02"]["confidence_basis"], "name+oui")
            self.assertEqual(by_mac["3C:EF:8C:00:00:03"]["confidence_basis"], "oui")
            self.assertNotIn("00:11:22:33:44:55", by_mac)
            evil = by_mac["02:00:00:00:00:04"]["ssid"]
            self.assertTrue(evil.startswith("'="), evil)
            self.assertNotIn("\x1b", evil)
            for r in rows:
                self.assertTrue(r["statement"].startswith("candidate:"))

    def test_demo_strict_profile_drops_generic_cam_ssid(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "run")
            rc, stdout, stderr = run_main(["--demo", "--profile", "strict", "-o", str(out)] + GATE)
            self.assertEqual(rc, 0, stderr)
            session = verify_outputs(self, out)
            self.assertEqual(session["profile"], "strict")
            rows = list(csv.DictReader(
                l for l in (out / "candidates.csv").read_text().splitlines() if not l.startswith("#")
            ))
            by_mac = {r["mac"]: r for r in rows}
            # Generic CAM formula-injection SSID should be gone under strict.
            self.assertNotIn("02:00:00:00:00:04", by_mac)
            # Wolfbox brand name remains.
            self.assertIn("02:1A:11:00:00:01", by_mac)

    def test_refuses_nonempty_output(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "keep.txt").write_text("evidence")
            rc, _, err = run_main(["--demo", "-o", td] + GATE)
            self.assertEqual(rc, 2)
            self.assertIn("not empty", err)


class PacketGateTests(unittest.TestCase):
    def test_demo_fixture_with_pcap_refuses_without_override(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "run")
            rc, _, err = run_main([
                "--demo", "--fixture", str(ROOT / "fixtures/demo_with_pcap.json"),
                "-o", str(out),
            ] + GATE)
            self.assertEqual(rc, 2)
            self.assertIn("Refusing to start", err)
            self.assertIn("pcap", err.lower())
            self.assertFalse(out.exists())

    def test_demo_fixture_with_pcap_override_recorded(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "run")
            rc, _, err = run_main([
                "--demo", "--fixture", str(ROOT / "fixtures/demo_with_pcap.json"),
                "--allow-packet-logging-risk", "-o", str(out),
            ] + GATE)
            self.assertEqual(rc, 0, err)
            self.assertIn("OPERATOR OVERRIDE", err)
            verify_outputs(self, out, expect_override=True)

    def test_default_demo_fixture_does_not_false_positive_on_disabled_text(self):
        risks = nw.packet_logging_warnings_from_active(
            json.loads((ROOT / "fixtures/demo_kismet_polls.json").read_text())["logging_active"]
        )
        self.assertEqual(risks, [])


class MockKismet(BaseHTTPRequestHandler):
    mode = "clean"  # clean | pcap | unreadable | badjson
    seen_paths: list = []
    seen_auth: list = []

    def log_message(self, *a):
        pass

    def _send(self, code, obj=None, raw: bytes | None = None):
        body = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        want = "Basic " + base64.b64encode(f"{FAKE_USER}:{FAKE_PASS}".encode()).decode()
        MockKismet.seen_auth.append(self.headers.get("Authorization", ""))
        return self.headers.get("Authorization") == want

    def do_GET(self):
        MockKismet.seen_paths.append(("GET", self.path))
        if not self._authed():
            return self._send(401, {"error": "auth"})
        if self.path == "/system/status.json":
            return self._send(200, {"kismet.system.version": "mock"})
        if self.path == "/logging/active.json":
            if MockKismet.mode == "unreadable":
                return self._send(500, {"error": "nope"})
            if MockKismet.mode == "badjson":
                return self._send(200, raw=b"not-json{")
            logs = [{"kismet.logfile.type": "kismetdb", "kismet.logfile.path": "/tmp/x.kismet"}]
            if MockKismet.mode == "pcap":
                logs.append({"kismet.logfile.type": "pcapng", "kismet.logfile.path": "/tmp/x.pcapng"})
            return self._send(200, logs)
        self._send(404, {})

    def do_POST(self):
        MockKismet.seen_paths.append(("POST", self.path))
        if not self._authed():
            return self._send(401, {"error": "auth"})
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        ctype = self.headers.get("Content-Type", "")
        if MockKismet.mode == "json415" and "application/json" in ctype:
            return self._send(415, {"error": "use form"})
        if "application/json" in ctype:
            fields = json.loads(raw.decode())["fields"]
        else:
            form = parse_qs(raw.decode())
            fields = json.loads(form["json"][0])["fields"]
        assert ["kismet.device.base.macaddr", "mac"] in fields
        if self.path.startswith("/devices/last-time/"):
            return self._send(200, [
                {"mac": "AA:BB:CC:00:00:09", "phy": "IEEE802.11", "type": "Wi-Fi AP", "channel": "6",
                 "ssid": "70mai_D08_1234", "manuf": "Unknown", "signal": -61, "first_time": 1, "last_time": 2},
                {"mac": "AA:BB:CC:00:00:0A", "phy": "IEEE802.11", "type": "Wi-Fi AP", "channel": "1",
                 "ssid": "CoffeeShop", "manuf": "Unknown", "signal": -70, "first_time": 1, "last_time": 2},
            ])
        self._send(404, {})


class LiveMockTests(unittest.TestCase):
    def setUp(self):
        MockKismet.seen_paths, MockKismet.seen_auth = [], []
        MockKismet.mode = "clean"
        self.srv = HTTPServer(("127.0.0.1", 0), MockKismet)
        self.th = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.th.start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        self._env = {k: os.environ.get(k) for k in ("KISMET_USER", "KISMET_PASS", "KISMET_API_TOKEN")}
        os.environ["KISMET_USER"], os.environ["KISMET_PASS"] = FAKE_USER, FAKE_PASS
        os.environ.pop("KISMET_API_TOKEN", None)

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_live_clean(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "live")
            rc, stdout, stderr = run_main(
                ["--kismet-url", self.url, "--duration", "0.01", "--no-clear", "-o", str(out)] + GATE
            )
            self.assertEqual(rc, 0, stderr)
            self.assertIn("70mai_D08_1234", stdout)
            verify_outputs(self, out)
            session = json.loads((out / "session.json").read_text())
            self.assertEqual(session["candidates"], 1)
            blob = stdout + stderr + "".join(p.read_text() for p in out.iterdir())
            self.assertNotIn(FAKE_PASS, blob)
            self.assertNotIn(base64.b64encode(f"{FAKE_USER}:{FAKE_PASS}".encode()).decode(), blob)
        self.assertFalse(any(".cmd" in p or p.endswith("pcap") for _, p in MockKismet.seen_paths))

    def test_live_pcap_refuses(self):
        MockKismet.mode = "pcap"
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "live")
            rc, _, err = run_main(
                ["--kismet-url", self.url, "--duration", "0.01", "--no-clear", "-o", str(out)] + GATE
            )
            self.assertEqual(rc, 2)
            self.assertIn("Refusing to start", err)
            self.assertFalse(out.exists())

    def test_live_pcap_override_recorded(self):
        MockKismet.mode = "pcap"
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "live")
            rc, _, err = run_main([
                "--kismet-url", self.url, "--duration", "0.01", "--no-clear",
                "--allow-packet-logging-risk", "-o", str(out),
            ] + GATE)
            self.assertEqual(rc, 0, err)
            verify_outputs(self, out, expect_override=True)

    def test_live_unreadable_logging_endpoint_refuses(self):
        MockKismet.mode = "unreadable"
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "live")
            rc, _, err = run_main(
                ["--kismet-url", self.url, "--duration", "0.01", "--no-clear", "-o", str(out)] + GATE
            )
            self.assertEqual(rc, 2)
            self.assertIn("unverifiable", err.lower())
            self.assertFalse(out.exists())

    def test_live_unreadable_override_recorded(self):
        MockKismet.mode = "unreadable"
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "live")
            rc, _, err = run_main([
                "--kismet-url", self.url, "--duration", "0.01", "--no-clear",
                "--allow-packet-logging-risk", "-o", str(out),
            ] + GATE)
            self.assertEqual(rc, 0, err)
            session = verify_outputs(self, out, expect_override=True)
            self.assertTrue(any("unverifiable" in w.lower() for w in session["warnings"]))

    def test_live_badjson_logging_endpoint_refuses(self):
        MockKismet.mode = "badjson"
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "live")
            rc, _, err = run_main(
                ["--kismet-url", self.url, "--duration", "0.01", "--no-clear", "-o", str(out)] + GATE
            )
            self.assertEqual(rc, 2)
            self.assertIn("unverifiable", err.lower())

    def test_bad_credentials_fail_cleanly(self):
        os.environ["KISMET_PASS"] = "wrong-value"
        with tempfile.TemporaryDirectory() as td:
            rc, stdout, stderr = run_main(
                ["--kismet-url", self.url, "--duration", "0.01", "-o", td + "/x"] + GATE
            )
            self.assertEqual(rc, 1)
            self.assertIn("HTTP 401", stderr)
            self.assertNotIn("wrong-value", stdout + stderr)

    def test_url_credentials_refused(self):
        with self.assertRaises(nw.KismetError):
            nw.KismetClient("http://u:p@127.0.0.1:2501")

    def test_live_falls_back_from_json_to_form(self):
        MockKismet.mode = "json415"
        with tempfile.TemporaryDirectory() as td:
            out = Path(td, "live")
            rc, stdout, stderr = run_main(
                ["--kismet-url", self.url, "--duration", "0.01", "--no-clear", "-o", str(out)] + GATE
            )
            self.assertEqual(rc, 0, stderr)
            self.assertIn("70mai_D08_1234", stdout)
            verify_outputs(self, out)


class KismetDBTests(unittest.TestCase):
    def _make_db(self, td: Path, *, with_packets: bool, with_data: bool = False) -> Path:
        db = td / "survey.kismet"
        conn = sqlite3.connect(db)
        conn.execute(
            "CREATE TABLE devices (first_time INT, last_time INT, devkey TEXT, phyname TEXT, "
            "devmac TEXT, strongest_signal INT, type TEXT, device BLOB)"
        )
        if with_packets:
            conn.execute("CREATE TABLE packets (ts_sec INT, packet BLOB)")
            conn.execute("INSERT INTO packets VALUES (1, x'00')")
        if with_data:
            conn.execute("CREATE TABLE data (ts_sec INT, data BLOB)")
            conn.execute("INSERT INTO data VALUES (1, x'00')")
        dev = {
            "kismet.device.base.macaddr": "AA:BB:CC:00:00:01",
            "kismet.device.base.phyname": "IEEE802.11",
            "kismet.device.base.type": "Wi-Fi AP",
            "kismet.device.base.manuf": "Unknown",
            "kismet.device.base.signal": {"kismet.common.signal.last_signal": -55},
            "dot11.device": {
                "dot11.device.last_beaconed_ssid_record": {"dot11.advertisedssid.ssid": "DDPAI_Z40"}
            },
        }
        conn.execute(
            "INSERT INTO devices VALUES (1,2,'k','IEEE802.11','AA:BB:CC:00:00:01',-55,'Wi-Fi AP',?)",
            (json.dumps(dev),),
        )
        conn.commit()
        conn.close()
        return db

    def test_kismetdb_with_packets_refuses(self):
        with tempfile.TemporaryDirectory() as td:
            db = self._make_db(Path(td), with_packets=True)
            out = Path(td, "out")
            rc, _, err = run_main(["--kismetdb", str(db), "-o", str(out)] + GATE)
            self.assertEqual(rc, 2)
            self.assertIn("Refusing to start", err)
            self.assertFalse(out.exists())

    def test_kismetdb_with_packets_override_recorded(self):
        with tempfile.TemporaryDirectory() as td:
            db = self._make_db(Path(td), with_packets=True)
            out = Path(td, "out")
            rc, stdout, err = run_main(
                ["--kismetdb", str(db), "--allow-packet-logging-risk", "-o", str(out)] + GATE
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("DDPAI_Z40", stdout)
            verify_outputs(self, out, expect_override=True)

    def test_kismetdb_data_rows_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            db = self._make_db(Path(td), with_packets=False, with_data=True)
            out = Path(td, "out")
            rc, _, err = run_main(["--kismetdb", str(db), "-o", str(out)] + GATE)
            self.assertEqual(rc, 2)
            self.assertIn("data-packet", err)
            self.assertFalse(out.exists())

    def test_kismetdb_clean(self):
        with tempfile.TemporaryDirectory() as td:
            db = self._make_db(Path(td), with_packets=False)
            out = Path(td, "out")
            rc, stdout, err = run_main(["--kismetdb", str(db), "-o", str(out)] + GATE)
            self.assertEqual(rc, 0, err)
            self.assertIn("DDPAI_Z40", stdout)
            verify_outputs(self, out)


class ScopeMainTests(unittest.TestCase):
    def test_scope_recorded_in_session(self):
        with tempfile.TemporaryDirectory() as td:
            sp = write_scope(Path(td))
            out = Path(td, "run")
            rc, _, err = run_main(["--demo", "--scope-file", str(sp), "-o", str(out)] + GATE)
            self.assertEqual(rc, 0, err)
            session = verify_outputs(self, out)
            self.assertTrue(session["scope_check"]["within_window"])
            self.assertTrue(session["scope_check"]["operator_authorized"])
            self.assertEqual(session["scope_check"]["location"], "Lab bay 3")


class HostClockTests(unittest.TestCase):
    def test_timedatectl_keys_ignore_print_order(self):
        # This host prints Timezone before NTPSynchronized. --value would swap them.
        vals = nw.parse_timedatectl_show("Timezone=America/New_York\nNTPSynchronized=yes\n")
        self.assertEqual(vals["NTPSynchronized"], "yes")
        self.assertEqual(vals["Timezone"], "America/New_York")

    def test_host_clock_shape(self):
        clock = nw.host_clock_state()
        self.assertIn(clock["ntp_synchronized"], {"yes", "no", "unknown"})
        self.assertNotIn("/", clock["ntp_synchronized"])
        self.assertIn("recorded_at_utc", clock)
        self.assertTrue(clock["recorded_at_utc"].endswith("Z"))


class SpanTests(unittest.TestCase):
    def test_rejects_non_finite_duration(self):
        rc, _, err = run_main(["--duration", "nan"])
        self.assertEqual(rc, 2)
        self.assertIn("duration", err.lower())

    def test_rejects_non_positive_interval(self):
        rc, _, err = run_main(["--interval", "inf"])
        self.assertEqual(rc, 2)
        self.assertIn("interval", err.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)

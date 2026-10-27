# The Night Watchman

A passive Kismet watcher that flags Wi-Fi and Bluetooth devices whose name or vendor resembles a wireless camera or dash cam.

The program file is **`nightwatchman.py`**.

The name comes from the Night Watchman in Wagner’s *Die Meistersinger von Nürnberg*. He walks the town after dark, calls the hour, and reports what he sees. He arrests no one. [The Magic Flute](https://github.com/scjeff/The-Magic-Flute) writes down every radio it hears, and [The Marksman](https://github.com/scjeff/The-Marksman) follows one mark. The Night Watchman reads what Kismet already heard and calls out the names that look like cameras.

**Beta:** This program is in beta. It can read a metadata-only Kismet 2026.10 session (see [Tests performed](#tests-performed)). I have not yet tested it with a wireless dashcam or a rearview camera in range, so the matching rules are still hypotheses.

**Data source:** this tool talks to [Kismet](https://www.kismetwireless.net/) over its REST API or reads a finished `.kismet` log. No Kismet source code is copied into this repository (the client only uses documented field names and HTTP endpoints).

**No affiliation:** this project is not affiliated with or endorsed by any brand or standards body it mentions.

**Authorized use only. No warranty.** Use only with written authorization / rules of engagement, or on your own devices. This program is free software under GPL-3.0-or-later and comes with **NO WARRANTY**, to the extent permitted by law (see [LICENSE](LICENSE)).

Python 3.9+ stdlib only. No `pip` packages. Licensed under **GPL-3.0-or-later**. Version **0.3.0**.

## Disclaimer: authorized use only

**The Night Watchman reads device metadata that Kismet collected:** MAC/BSSID, SSID, Bluetooth advertised name, vendor name, channel, signal level, first and last seen, and device type.

Use it **only** where you have legal authority, for example:

- your own network and your own devices
- an authorized survey under a signed Rules of Engagement (ROE)
- written permission from the network or property owner

Unauthorized interception of communications can be a crime. You are responsible for local law. The authors assume **no liability** for misuse.

**The gate records the operator's attestation of authorization. It does not verify the ROE.** Typing `YES` or passing `--i-have-roe` stores that attestation in the session. The tool does not open, validate, or confirm the ROE document itself.

**This tool does not replace the site owner's or operator's own approval** before a receiver is brought into a controlled area. Site security rules and written authorization / rules of engagement still apply. A valid ROE for this tool is not that site approval.

What the tool does and does not do:

- It never touches a radio. Kismet does the receiving. The Night Watchman reads Kismet's REST API (default `http://127.0.0.1:2501`) or a finished `.kismet` log, opened read-only.
- It sends no frames and does no active probing, injection, deauthentication, association, pairing, or GATT reads.
- It does not read, decode, or keep packets, payloads, or video. Metadata only.
- It matches **SSID, Bluetooth name, and OUI vendor patterns only**. It does not fingerprint traffic.
- Every hit is written as **"candidate: SSID resembles a camera/dash cam"** (or the vendor / Bluetooth variant) with a confidence note. It never says "this is a camera".
- **Attribution is left to site security or the investigating party.** The report does not tie a device to a person, vehicle, or purpose.

## Authorization gate

The tool refuses to start without all three of:

| Flag | What it records |
| --- | --- |
| `--roe-id` | Rules of Engagement ID |
| `--auth-ref` | Authorization reference (letter, ticket, or approval number) |
| `--operator` | Operator name |

You also have to type `YES`, or pass `--i-have-roe` when you run it non-interactively. All three values appear in the console banner and in the header of every output file. A value with control characters is refused.

### Scope file (`scope.template.json`)

> **The window, location and operator ("Jane Doe") in the template are examples only. Replace every value; never leave placeholders in a real scope file.**

`--scope-file FILE` is optional. Prefer the JSON template next to the script. Required JSON fields:

| Field | Meaning |
| --- | --- |
| `protocols` | Non-empty list, e.g. `["Wi-Fi", "Bluetooth"]` |
| `location` | Building / floor / area covered by the ROE |
| `authorized_time_window.start_utc` / `end_utc` | ISO-8601 UTC window |
| `authorized_operators` | Non-empty list of operator names |

The file's SHA-256 is recorded. For JSON scopes, `session.json` notes whether the run start fell inside the window and whether the operator name is in the authorized list. Mismatches **warn by default**. Pass `--strict-scope` to refuse to start on a mismatch (also refuses if no scope file is given).

A plain-text scope file is still accepted: its hash is recorded and structured checks are skipped.

## Packet logging: fail closed

By default the tool **refuses to start** when:

- Kismet reports an active pcap / packet log (`pcapng`, `pcapppi`, or `pcap` type, or a `.pcap` / `.pcapng` path), or
- `/logging/active.json` cannot be read or parsed (live mode), or
- a `.kismet` file contains rows in its `packets` table or its `data` table (data-packet rows)

Pass `--allow-packet-logging-risk` to override. The override is written into every output header, the console banner, and `session.json`. Detection uses log-type fields and path suffixes only; a note that says "pcap disabled" does not trip it.

## Data handling

The raw Kismet log and a live Kismet session hold metadata on **every device in range**, including bystanders' phones and vehicles. Treat that store as sensitive. The candidate CSV and JSON rows also keep device addresses (MAC / BSSID).

- **Name a custodian** for the session directory and any Kismet log this survey produces.
- **Set retention** from the ROE and site policy. Retention periods are **not specified by this tool**; they are a planning assumption to be taken from site policy.
- The **ROE must say** whether bystander metadata may be collected and for how long it is kept.

## Quick start

```bash
python3 nightwatchman.py --self-test

# Offline demo: bundled fixture, no Kismet, no radio
python3 nightwatchman.py --demo \
  --roe-id DEMO-ROE-001 --auth-ref DEMO-AUTH-42 --operator "Jane Doe" --i-have-roe
```

Live, against a Kismet server that you started under the ROE (pcap logging off):

```bash
export KISMET_USER=...        # or: export KISMET_API_TOKEN=...
read -rs KISMET_PASS && export KISMET_PASS   # typed, not stored in shell history
python3 nightwatchman.py \
  --roe-id ROE-2026-014 --auth-ref "Approval 7731" --operator "Jane Doe" \
  --scope-file scope.json --i-have-roe \
  --kismet-url http://127.0.0.1:2501 --interval 5 --duration 1800
```

From a finished Kismet log, read-only (the log must not contain packet rows, or pass the override):

```bash
python3 nightwatchman.py --kismetdb Kismet-20261027-12-00-00-1.kismet \
  --roe-id ROE-2026-014 --auth-ref "Approval 7731" --operator "Jane Doe" --i-have-roe
```

Credentials come only from `KISMET_USER` / `KISMET_PASS` or `KISMET_API_TOKEN`. A URL that contains credentials is refused. Credentials are never printed or written to a report. The session records only the auth type (`basic`, `token`, or `none`).

## Kismet configuration: metadata only

Run Kismet so that it records device metadata and no packets. Put these lines in `kismet_site.conf`, which overrides `kismet_logging.conf`:

```
# Device metadata only: kismetdb log, no pcap logs
log_types=kismet
kis_log_packets=false
kis_log_data_packets=false
kis_log_duplicate_packets=false
# Strip data-frame contents from the web UI and API
hidedata=true
# API on loopback only
httpd_bind_address=127.0.0.1
```

Leave `pcapng` and `pcapppi` out of `log_types`. To keep no log at all and use only the live API, start Kismet with `-n` (`--no-logging`).

A stock `/etc/kismet/kismet_logging.conf` often already sets `log_types=kismet` and still sets `kis_log_packets=true`. That log has a `packets` table, and this tool refuses it. Put the packet lines in `kismet_site.conf` or pass an `--override` file. `kismet_site.conf` is the file Kismet merges over the packaged logging config.

Kismet 2026.10 reports the log type under `kismet.log.type_driver` → `kismet.logfile.type.class`, not as a top-level `kismet.logfile.type`. A metadata log's class is `kismet`. Its description mentions the word "packet"; that text is not treated as packet logging. A class of `pcapng`, `pcapppi`, or `pcap` is refused even when the path does not end in `.pcap` or `.pcapng`.

The first live poll reads every device the server already holds (`/devices/last-time/0`). Later polls ask only for devices heard in the last few seconds. Kismet's simplified SSID field is the number `0` when a device has no SSID. Bluetooth advertised names are taken from `bluetooth.device.device_name` when that field exists, otherwise from `commonname` / `name` when those are not just the MAC. Client probe lists are not matched: a phone that looked for a camera network is not reported as the camera.

The Night Watchman does not start Kismet and does not open a radio. Start Kismet yourself, with packet logging off, then point this program at it. On Kismet 2026.10 a MediaTek mt76 / Panda adapter is listed twice (`mt7921-0` usbwifi, and `wlx…` linuxwifi). Do not open both. Opening `mt7921-0` detaches the kernel driver, and putting it back needs root. The kernel name works through `kismet_cap_linux_wifi`. Do not capture on the interface that carries your only route.

Kismet may leave a radiotap interface behind when it exits. The name is often `kismon0`. Removing it needs root (`sudo iw dev kismon0 del`).

## Tests performed

This program is in beta. The notes below are about the client.

Offline, `python3 -m unittest discover -s tests -v` runs 80 tests against a mock Kismet and fixtures. Those tests cover the Kismet 2026.10 log-type shape, an empty SSID stored as the number `0`, and beaconed names rather than probe requests.

The live reader and the `--kismetdb` reader were both exercised against a metadata-only Kismet 2026.10 session. I have not yet tested the program with a wireless dashcam or a rearview camera present. A match is only a name or vendor hypothesis. An empty result is not a calibration of the watchlist, and it is not evidence that no camera is there.

## Target devices

The committed watchlist is brand-name based and is an **unverified seed**. Device-specific model strings do not belong in the public tree. Put them in a local overlay (`nightwatchman.local.json`, ignored by git, or `--watchlist-extra PATH`; see `nightwatchman.local.example.json`).

Only a unit that actually opens a Wi-Fi hotspot or advertises a Bluetooth name can be a Kismet candidate. Receive-only parts (for example a GPS antenna) and wired accessories (for example a wired rear camera) transmit nothing for Kismet to hear. Product listings often do not document a unit's SSID format, band, or Bluetooth name; do not invent them. Calibrate every pattern against a real owned unit in a lab before survey use.

## Watchlist (`nightwatchman.json`) and profiles


| Key | Matched against |
| --- | --- |
| `ssid_patterns` | SSID and Bluetooth advertised name. Defaults include Wolfbox, VIOFO, 70mai, Garmin, DDPAI, Rexing, Nextbase, Thinkware, BlackVue, Vantrue, YI, Wyze, Ring, Arlo, Hikvision/EZVIZ, Dahua/Imou, Reolink, plus generic IPC / CAM / DashCam / DVR / FPV |
| `vendor_patterns` | The vendor name Kismet gives for the MAC. If Kismet has none, the optional `ieee_mac_vendors.csv` (The Magic Flute's `prefix,vendor` file) is used |
| `oui_prefixes` | Exact MAC prefixes that you copy from the IEEE registry. Empty by default so that no prefix is guessed |
| `trend` | `min_samples`, `steady_db`, `varying_db` for the signal hint |

**The shipped watchlist is an unverified seed.** Calibrate it against a real owned unit in a lab before you trust it on a survey. Brand names, firmware defaults, and OUI assignments change. The committed file keeps **brand and generic patterns only** (including the Wolfbox brand pattern). Device-specific model strings belong in a local overlay.

### Local overlay (`nightwatchman.local.json`)

Optional patterns (for example listing model strings) merge onto the base watchlist:

- **Auto-loaded:** a sibling `nightwatchman.local.json` (same directory as the base `nightwatchman.json`) is loaded automatically whenever that file exists. The session records it as `overlay_used.json` with its own SHA-256
- Or passed explicitly with `--watchlist-extra PATH`, which replaces the auto-loaded sibling file
- **Base-only run:** when a `nightwatchman.local.json` is present, run with `--watchlist-extra nightwatchman.local.example.json`. That loads only the placeholder pattern (`example-model-123`) instead of your local model strings, so in practice only the base watchlist matches. There is no separate "no overlay" flag
- Ship template: `nightwatchman.local.example.json` (placeholder only). The real local file is **gitignored** and must not be committed
- Overlay `ssid_patterns`, `vendor_patterns`, `model_patterns`, and `oui_prefixes` are appended and validated with the same rules as the base file. An invalid overlay pattern refuses to start
- `model_patterns` are a separate low-confidence match (listing model string; unverified as SSID/BT). Under `--profile strict` they are dropped; the Wolfbox **brand** label remains

`--profile broad` (default) uses the full watchlist plus any overlay. `--profile strict` keeps brand names and vendor patterns only, and drops generic IPC / CAM / DashCam / DVR / FPV name rules and all model-string patterns.

Patterns are case-insensitive Python regexes, validated at startup. Names are cut to 248 characters before matching. The config file's SHA-256 goes into the session, and a copy is saved as `config_used.json`.

### Confidence

| Basis | Note |
| --- | --- |
| `name` / `bt_name` | Low. Names can be set by the user and can be spoofed |
| `model` | Low. Listing model string only; unverified as an SSID or Bluetooth name |
| `oui` | Low. The vendor also makes products that are not cameras. **Weighted the same as name-only** |
| `name+oui` | Medium. The name and the vendor agree. Still unverified |
| `model+oui` | Low-medium. Model string and vendor agree; model string still unverified as SSID |

Labels are sticky across polls: a MAC that matched once stays a candidate even if a later poll shows a benign SSID. Basis is recomputed when new evidence arrives (for example OUI-only, then a name with an empty vendor, becomes `name+oui`). A later **brand** name label replaces an earlier **generic** one (for example `Cam-Lobby` / Generic camera followed by `WOLFBOX_MODEL123` ends as Wolfbox); brand labels are not downgraded.

The **signal trend** (`steady`, `mixed`, `varying`) is the spread of RSSI samples. It is a hint only.

## Outputs

Default directory: `./nightwatchman_YYYYMMDDTHHMMSSZ/`. The tool refuses to write into a directory that is not empty.

| File | Contents |
| --- | --- |
| `candidates.csv` | `#` header lines (ROE ID, authorization, operator, scope hash, config hash, clock, notices), then one row per candidate |
| `candidates.json` | Same header, session, and candidate rows |
| `session.json` | Tool version, gate values, attestation wording, profile, packet-logging override, scope check, host clock (NTP sync best-effort), mode, source, start and end times, config SHA-256, warnings, counts |
| `config_used.json` | Exact copy of the watchlist used |
| `SHA256SUMS` | SHA-256 of each file above (`sha256sum -c SHA256SUMS`) |

All files are set read-only (`0444`) after the run. **`0444` plus `SHA256SUMS` supports integrity but is NOT tamper-proof.** Record the `SHA256SUMS` digest out-of-band (ROE log or custodian handoff). `session.json` also records the host clock's NTP sync state when `timedatectl` is available (`yes` / `no` / `unknown`) and the UTC timestamps.

SSIDs and names are attacker-controlled. The tool strips control characters, ANSI escapes, and bidi/zero-width characters before it prints or writes them, and caps their length. Any CSV text cell that starts with `= + - @ | %`, a tab, or a CR is prefixed with `'`. The exact bytes are kept as hex (`ssid_hex`, `bt_name_hex`) as evidence.

## Control mapping (800-53 control families)

| Control | How the tool supports it |
| --- | --- |
| **AC-18** Wireless Access | Finds wireless emitters that may be unauthorized (camera and dash cam hotspots) for the AC-18 review |
| **CM-8** System Component Inventory | Candidate list with MAC, vendor, and SSID that you can reconcile against the authorized wireless inventory |
| **CM-8(3)** Automated Unauthorized Component Detection | Automated comparison of observed names/vendors against a watchlist of camera-like patterns |
| **SI-4** System Monitoring | Periodic passive monitoring of the wireless environment. Output feeds analysis and escalation, not automated response |
| **SI-4(14)** Wireless Intrusion Detection | Passive-only detection of wireless emitters whose advertisements resemble camera or dash cam devices |
| **AU-3** Content of Audit Records | Each record carries what (candidate and basis), when (first and last seen, UTC), where (channel), the source (MAC/BSSID), and who ran it (operator, ROE ID, authorization). SHA-256 sums and read-only files support integrity (AU-9) but are not tamper-proof |

This mapping shows what the tool's output can support. It is not a control assessment.

## Limitations

- **No candidates does not show that no camera is present.** A renamed, hidden, wired, record-only, cellular, or analog camera will not match. An empty candidate list is not a clearance.
- **Pattern matching only.** Expect both misses and false hits. A coffee shop called "Camden" is not flagged; "Cam-Lobby" is.
- **Sticky candidates.** Once a MAC is flagged, it stays in the report for that run even if a later poll shows a benign SSID. That is intentional so a brief camera-like advertisement is not lost. A later brand match upgrades an earlier generic name label; generics never overwrite a brand label.
- **Bluetooth names** are flagged only when Kismet has a Bluetooth source and the device advertises a name. Random BLE addresses have no IEEE vendor.
- **Vendor lookup** depends on Kismet's `manuf` field or the optional IEEE CSV. Locally administered (randomized) MACs are never looked up.
- **Trend** is a hint. It is not a position, a range, or a motion detector.
- **Kismet API field names** follow the same simplified-field paths The Magic Flute uses. If a build rejects the `dot11` fields, the tool falls back to base fields and tries `commonname` / `name` as the SSID when they are not just the MAC. Kismet 2026.10 returns SSID `0` when there is no SSID. The `/logging/active.json` check reads flat type fields, the 2026 nested `kismet.log.type_driver` class, and `.pcap` / `.pcapng` path suffixes. A description that says "packet" does not trip it.
- **Probe requests are ignored.** Only beaconed or advertised SSIDs, Bluetooth advertised names, and vendor names are matched.
- **Testing:** 80 offline tests pass against a mock Kismet and fixtures. The live reader and the `--kismetdb` reader were exercised on a metadata-only Kismet 2026.10 session. I have not yet tested the program with a wireless dashcam or a rearview camera present, so the watchlist is still an unverified seed.

## Self-test

```bash
python3 nightwatchman.py --self-test
# or
python3 -m unittest discover -s tests -v
```

## License

The Night Watchman is free software under the **GNU General Public License v3.0 or later** (GPL-3.0-or-later). See [LICENSE](LICENSE).

The GPL covers copyright in the software. It does **not** authorize wireless collection.

## Repository contents

```
nightwatchman.py                 # watcher, gate, reports (GPL-3.0-or-later)
nightwatchman.json               # editable brand/generic watchlist (unverified seed)
nightwatchman.local.example.json # EXAMPLE overlay (placeholder); copy to nightwatchman.local.json
scope.template.json              # JSON scope file template
fixtures/demo_kismet_polls.json  # synthetic Kismet responses for --demo
fixtures/demo_with_pcap.json     # same fixture with an active pcap log (override tests)
tests/test_nightwatchman.py      # offline unit tests
SAMPLE_DEMO_RUN.txt              # captured --demo output
README.md
LICENSE                          # GNU GPL v3
.gitignore
```

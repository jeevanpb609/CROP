"""
CROP — Edge-IIoTset PPS trace builder (CP2, v1.2)
Normal baseline : Soil_Moisture.csv  (truncated 'tod' timestamps, 100% parse)
Attack flood    : DDoS_UDP_Flood_attack.pcap (real per-packet epoch timestamps)
                  -- the attack CSV's timing columns are defective (frame.time
                  holds spoofed src IPs; udp.time_delta is 0.0 because every
                  flood packet opens a new UDP stream), so pcap is authoritative.
Pure stdlib. Memory-safe streaming. No Wireshark/tshark required.

Usage:
    python tools/build_pps_trace.py --dry-run
    python tools/build_pps_trace.py
"""
import csv, re, json, os, sys, struct, argparse
from collections import Counter
from datetime import datetime

CSV_NORMAL = r"C:\VSCode\crop_simulation\datasets\raw\Soil_Moisture.csv"
CSV_ATTACK = r"C:\VSCode\crop_simulation\datasets\raw\DDoS_UDP_Flood_attack.csv"
PCAP_ATTACK = r"C:\VSCode\crop_simulation\datasets\raw\DDoS_UDP_Flood_attack.pcap"
OUT_JSON = r"C:\VSCode\crop_simulation\gateway\traffic_trace.json"

NORMAL_SECONDS = 30
ATTACK_SECONDS = 20
THRESHOLD_PPS = 500
PROBE_ROWS = 500

TS_FULL = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}),\s*(\d{4})\s+(\d{2}):(\d{2}):(\d{2})")
TS_TOD = re.compile(r"^(\d{4})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?")
MONTHS = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], 1)}

try:
    csv.field_size_limit(10_000_000)
except Exception:
    pass

def _isfloat(v):
    try:
        float(v)
        return True
    except (TypeError, ValueError):
        return False

def sniff_delimiter(path):
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        head = f.readline()
    return "\t" if head.count("\t") > head.count(",") else ","

class TsParser:
    def __init__(self):
        self.mode = None
        self.day_offset = 0
        self.last_tod = None
        self.month_base = {}
    def _full(self, v):
        m = TS_FULL.match(v)
        if not m:
            return None
        mon, day, yr, hh, mi, ss = m.groups()
        key = (mon, yr)
        if key not in self.month_base:
            try:
                self.month_base[key] = datetime(int(yr), MONTHS[mon], 1).timestamp()
            except ValueError:
                return None
        return (int(self.month_base[key]) + (int(day) - 1) * 86400
                + int(hh) * 3600 + int(mi) * 60 + int(ss))
    def _tod(self, v):
        m = TS_TOD.match(v)
        if not m:
            return None
        _yr, hh, mi, ss, _frac = m.groups()
        t = int(hh) * 3600 + int(mi) * 60 + int(ss)
        if self.last_tod is not None and t < self.last_tod - 3600:
            self.day_offset += 86400
        self.last_tod = t
        return self.day_offset + t
    def parse(self, v):
        v = (v or "").strip()
        if not v:
            return None
        if self.mode == "full":
            return self._full(v)
        if self.mode == "tod":
            return self._tod(v)
        if self.mode == "epoch":
            try:
                return int(float(v))
            except ValueError:
                return None
        for mode, fn in (("full", self._full), ("tod", self._tod)):
            t = fn(v)
            if t is not None:
                self.mode = mode
                return t
        try:
            t = int(float(v))
            self.mode = "epoch"
            return t
        except ValueError:
            return None

def profile_csv(path, label, verbose):
    delim = sniff_delimiter(path)
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        reader = csv.reader(f, delimiter=delim)
        header = next(reader, None)
        if not header:
            raise SystemExit(f"[FAIL] {path}: empty file")
        hlen = len(header)
        ts_idx = next((i for i, n in enumerate(header) if n.strip() == "frame.time"), 0)
        d_idx = next((i for i, n in enumerate(header) if n.strip() == "udp.time_delta"), None)
        probe = []
        for _ in range(PROBE_ROWS):
            row = next(reader, None)
            if row is None:
                break
            probe.append(row)
        lens = Counter(len(r) for r in probe)
        shift = 1 if (lens and lens.most_common(1)[0][0] == hlen - 1) else 0
        p = TsParser()
        hits = sum(1 for r in probe if len(r) > ts_idx and p.parse(r[ts_idx]) is not None)
        ts_rate = hits / len(probe) if probe else 0.0
        mode = "ts" if ts_rate >= 0.9 else "delta"
        eff_delta = None
        if mode == "delta" and d_idx is not None:
            for cand in (d_idx - shift, d_idx):
                if cand < 0:
                    continue
                ok = sum(1 for r in probe if len(r) > cand and _isfloat(r[cand]))
                if ok / len(probe) >= 0.5:
                    eff_delta = cand
                    break
            if eff_delta is None:
                mode = "fail"
        raw_ts = [r[ts_idx] for r in probe[:3] if len(r) > ts_idx]
        counts = Counter()
        parser = TsParser()
        t_acc = 0.0
        parsed = bad = 0
        def consume(row):
            nonlocal t_acc, parsed, bad
            if mode == "ts":
                ts = parser.parse(row[ts_idx]) if len(row) > ts_idx else None
                if ts is None:
                    bad += 1
                    return
                counts[ts] += 1
                parsed += 1
            elif mode == "delta":
                try:
                    t_acc += float(row[eff_delta]) if len(row) > eff_delta else 0.0
                except ValueError:
                    pass
                counts[int(t_acc)] += 1
                parsed += 1
            else:
                bad += 1
        for r in probe:
            consume(r)
        for row in reader:
            consume(row)
    vals = sorted(counts)
    base = vals[0] if vals else 0
    stats = {
        "file": os.path.basename(path), "role": label, "bytes": os.path.getsize(path),
        "delimiter": "TAB" if delim == "\t" else "COMMA",
        "header_cols": hlen, "row_len_probe": dict(lens), "shift": shift,
        "mode": mode, "ts_parse_rate_pct": round(100.0 * ts_rate, 2),
        "delta_col_index": eff_delta, "raw_ts_samples": raw_ts,
        "rows": parsed + bad, "parsed": parsed, "skipped": bad,
        "span_rel_s": [0, vals[-1] - base] if vals else None,
        "pps_max": max(counts.values()) if counts else 0,
        "pps_mean": round(sum(counts.values()) / len(counts), 2) if counts else 0,
        "_counts": Counter({k - base: v for k, v in counts.items()}),
    }
    if verbose:
        print(f"\n=== {label}: {stats['file']} ===")
        for k in ("mode", "rows", "parsed", "skipped", "span_rel_s", "pps_max", "pps_mean"):
            print(f"  {k:18}: {stats[k]}")
        print(f"  raw_ts_samples    : {raw_ts}")
    return stats

def pcap_counts(path):
    """Stream classic pcap or pcapng; bucket packet arrival epoch-seconds."""
    counts = Counter()
    rows = 0
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\xd4"):
            fmt = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
            f.read(20)
            while True:
                hdr = f.read(16)
                if len(hdr) < 16:
                    break
                ts_sec, _frac, caplen, _olen = struct.unpack(fmt + "IIII", hdr)
                f.seek(caplen, 1)
                counts[ts_sec] += 1
                rows += 1
        elif magic == b"\x0a\x0d\x0d\x0a":
            fmt = "<"
            units = {}
            while True:
                bh = f.read(8)
                if len(bh) < 8:
                    break
                btype, blen = struct.unpack("<II", bh)
                body = f.read(blen - 12)
                if len(body) < blen - 12:
                    break
                if btype == 0x0A0D0D0A:
                    bom = struct.unpack_from("<I", body, 0)[0]
                    fmt = "<" if bom == 0x1A2B3C4D else ">"
                    btype, blen = struct.unpack(fmt + "II", bh)
                elif btype == 0x00000001:                      # IDB
                    unit = 1e-6
                    off = 8
                    while off + 4 <= len(body):
                        oc, ol = struct.unpack_from(fmt + "HH", body, off)
                        off += 4
                        if oc == 9 and ol >= 1:
                            v = body[off]
                            unit = (10 ** -v) if v < 128 else (2 ** -v)
                        off += ol + ((4 - ol % 4) % 4)
                        if oc == 0:
                            break
                    units[len(units)] = unit
                elif btype == 0x00000006:                      # EPB
                    iid, tsh, tsl, _cap, _olen = struct.unpack_from(fmt + "IIIII", body, 0)
                    t = ((tsh << 32) | tsl) * units.get(iid, 1e-6)
                    counts[int(t)] += 1
                    rows += 1
        else:
            raise SystemExit(f"[FAIL] {path}: unknown capture magic {magic!r}")
    return counts, rows

def profile_pcap(path, label, verbose):
    counts, rows = pcap_counts(path)
    vals = sorted(counts)
    base = vals[0] if vals else 0
    rel = Counter({k - base: v for k, v in counts.items()})
    stats = {
        "file": os.path.basename(path), "role": label, "bytes": os.path.getsize(path),
        "mode": "pcap", "rows": rows, "parsed": rows, "skipped": 0,
        "span_rel_s": [0, vals[-1] - base] if vals else None,
        "pps_max": max(counts.values()) if counts else 0,
        "pps_mean": round(sum(counts.values()) / len(counts), 2) if counts else 0,
        "_counts": rel,
    }
    if verbose:
        print(f"\n=== {label}: {stats['file']} ===")
        for k in ("mode", "rows", "span_rel_s", "pps_max", "pps_mean"):
            print(f"  {k:18}: {stats[k]}")
    return stats

def best_window(counts, want):
    if not counts:
        return []
    secs = sorted(counts)
    runs, start = [], secs[0]
    for prev, cur in zip(secs, secs[1:]):
        if cur != prev + 1:
            runs.append((start, prev))
            start = cur
    runs.append((start, secs[-1]))
    best, best_sum = [], -1
    for a, b in runs:
        length = min(want, b - a + 1)
        for s in range(a, b - length + 2):
            total = sum(counts.get(s + i, 0) for i in range(length))
            if total > best_sum:
                best_sum = total
                best = [counts.get(s + i, 0) for i in range(length)]
    return best

def max_sustained(win, k=3):
    if not win:
        return 0
    if len(win) < k:
        return max(win)
    return max(sum(win[i:i + k]) for i in range(len(win) - k + 1)) / k

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    print("CROP trace builder v1.2 — streaming Edge-IIoTset captures...")
    norm = profile_csv(CSV_NORMAL, "NORMAL baseline", True)
    if os.path.exists(PCAP_ATTACK):
        atk = profile_pcap(PCAP_ATTACK, "ATTACK flood (pcap timestamps)", True)
    else:
        print(f"\n[WARN] {PCAP_ATTACK} not found — CSV fallback has NO usable timing "
              f"(frame.time=spoofed IPs, udp.time_delta=0.0). Download the pcap.")
        atk = profile_csv(CSV_ATTACK, "ATTACK flood (csv, timing defective)", True)

    ok = (norm["mode"] != "fail" and atk["mode"] != "fail"
          and norm["parsed"] > 1000 and atk["parsed"] > 1000
          and (atk["span_rel_s"][1] > 5 if atk["span_rel_s"] else False))
    if not ok:
        print("\n[FAIL] timing unusable — paste this output back.")
        sys.exit(1)

    norm_win = best_window(norm["_counts"], NORMAL_SECONDS)
    atk_win = best_window(atk["_counts"], ATTACK_SECONDS)
    print(f"\nNormal window ({len(norm_win)}s): {norm_win[:12]}")
    print(f"Attack window ({len(atk_win)}s): max={max(atk_win) if atk_win else 0} pps, first12={atk_win[:12]}")

    norm_sus = max_sustained(norm_win, 3)
    atk_sus = max_sustained(atk_win, 3)
    print(f"Sustained-3s mean: normal={norm_sus:.0f} pps, attack={atk_sus:.0f} pps (threshold {THRESHOLD_PPS})")
    if atk_sus <= THRESHOLD_PPS:
        print("[WARN] attack sustained rate <= threshold — alert will not fire.")
    if norm_sus >= THRESHOLD_PPS:
        print("[WARN] normal sustained rate >= threshold — false positives likely.")

    if args.dry_run:
        print("\nDRY RUN complete — nothing written.")
        return

    label = "DDoS_UDP"
    seq = ([{"pps": p, "label": "Normal", "segment": "normal-pre"} for p in norm_win] +
           [{"pps": p, "label": label, "segment": "attack"} for p in atk_win] +
           [{"pps": p, "label": "Normal", "segment": "normal-post"} for p in norm_win])
    for s in (norm, atk):
        s.pop("_counts", None)
    trace = {
        "provenance": {
            "dataset": "Edge-IIoTset (Ferrag et al., 2022)",
            "citation": "M. A. Ferrag, O. Friha, D. Hamouda, L. Maglaras, H. Janicke, "
                        "'Edge-IIoTset: A New Comprehensive Realistic Cyber Security Dataset of IoT "
                        "and IIoT Applications for Centralized and Federated Learning', TechRxiv, 2022, "
                        "doi:10.36227/techrxiv.18857336.v1",
            "source_url": "https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot",
            "files": [norm, atk],
            "attack_csv_timing_defect": "Attack CSVs ship frame.time=spoofed source IPs and "
                                        "udp.time_delta=0.0 (each flood packet opens a new UDP stream); "
                                        "attack timing is therefore taken from pcap record timestamps.",
            "builder": "tools/build_pps_trace.py v1.2",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "note": "Per-second packet rates derived OFFLINE from raw captures; the gateway REPLAYS "
                    "this trace. Not live packet capture.",
        },
        "threshold_pps": THRESHOLD_PPS,
        "sustained_windows": 3,
        "loop": True,
        "sequence": seq,
    }
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(trace, f, indent=1)
    print(f"\nWROTE {OUT_JSON} — {len(seq)} replay windows. Reply WORKS for CP3.")

if __name__ == "__main__":
    main()
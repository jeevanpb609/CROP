"""
CROP — Layer 3 Cyber-Physical Data Integrity Engine (v2.4.0, CP5)
YAML-driven rule engine. Rules, weights and thresholds live in rules.yaml
(mounted read-only into the container; path overridable via CROP_RULES_FILE).
This module supplies the typed rule handlers — the engine's "instruction
set" — that declarative rules invoke:
    cross_sensor_conflict, range_plausibility, rate_of_change,
    command_effect, stuck_replay, corroboration
Extension points:
  * New rule INSTANCE (new sensor pair) : add a YAML entry, no code change.
  * New rule TYPE                       : add a handler to HANDLERS.
Fallback: missing rules.yaml or missing PyYAML -> identical built-in defaults.
"""
from __future__ import annotations

import os
import time as _time
from collections import deque
from dataclasses import dataclass, field

try:
    import yaml as _yaml
except Exception:
    _yaml = None

RULES_FILE = os.getenv("CROP_RULES_FILE") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "rules.yaml")

# ---- built-in defaults (mirror of rules.yaml; fallback only) ---------------
DEFAULT_CONFIG = {
    "spoofed_at_or_below": 40,
    "degraded_at_or_below": 70,
    "history_max": 512,
}
DEFAULT_RULES = [
    {"id": "R1", "type": "cross_sensor_conflict", "weight": 100,
     "description": "Rainfall > 10 mm/hr while soil moisture < 20%: precipitation without soil wetting is physically impossible.",
     "params": {"rain_gt": 10.0, "moisture_lt": 20.0}},
    {"id": "R2", "type": "range_plausibility", "weight": 70,
     "description": "Readings outside physical sensor bounds (moisture 0-100%, rain 0-300 mm/hr, temp -20..60 C).",
     "params": {"moisture": [0.0, 100.0], "rain": [0.0, 300.0], "temp": [-20.0, 60.0]}},
    {"id": "R3", "type": "rate_of_change", "weight": 50,
     "description": "Soil moisture change > 5% within 60 s without rain onset or irrigation command.",
     "params": {"window_s": 60.0, "max_pct_per_window": 5.0, "rain_onset_gt": 10.0}},
    {"id": "R4", "type": "command_effect", "weight": 40,
     "description": "Valve commanded OPEN for >= 300 s with < 1% moisture response.",
     "params": {"min_open_s": 300.0, "min_delta_pct": 1.0}},
    {"id": "R5", "type": "stuck_replay", "weight": 30,
     "description": "Zero moisture variance across 8 readings while environment dynamic.",
     "params": {"min_readings": 8, "dynamic_rain_gt": 10.0}},
    {"id": "R6", "type": "corroboration", "weight": -10,
     "description": "Rainfall and soil moisture mutually consistent: trust bonus.",
     "params": {"rain_gt": 10.0, "moisture_gt": 50.0}},
]


def load_rules():
    """Return (config, rules, source). Prefers rules.yaml; falls back safely."""
    if _yaml is not None and os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                doc = _yaml.safe_load(f) or {}
            cfg = {**DEFAULT_CONFIG, **(doc.get("engine") or {})}
            rules = doc.get("rules") or []
            if rules:
                return cfg, rules, os.path.basename(RULES_FILE)
        except Exception as e:
            print(f"[Layer 3] rules.yaml parse failed ({e}); using built-in defaults")
    return dict(DEFAULT_CONFIG), list(DEFAULT_RULES), "built-in defaults"


CONFIG, RULES, RULES_SOURCE = load_rules()
RULE_META = [
    {"rule_id": r["id"], "name": r["type"], "weight": r["weight"],
     "description": r.get("description", "")}
    for r in RULES
]


@dataclass
class Observation:
    ts: float
    moisture: float
    rain: float
    temp: float | None = None
    valve_open: bool | None = None


@dataclass
class Evaluation:
    ts: float
    trust_score: int
    verdict: str
    valve_command: str | None
    action_taken: str
    reason: str
    fired_ids: list = field(default_factory=list)
    evidence: list = field(default_factory=list)


# ---- typed rule handlers: (engine, obs, params) -> (fired, inputs, threshold, explanation)
def _h_cross_sensor_conflict(engine, obs, p):
    fired = obs.rain > p["rain_gt"] and obs.moisture < p["moisture_lt"]
    exp = (f"Rainfall={obs.rain} mm/hr but soil moisture={obs.moisture}% "
           f"(physically impossible)") if fired else ""
    return fired, {"rain_mm_per_hr": obs.rain, "moisture_pct": obs.moisture}, \
        {"rain_gt": p["rain_gt"], "moisture_lt": p["moisture_lt"]}, exp


def _h_range_plausibility(engine, obs, p):
    viol = []
    if not (p["moisture"][0] <= obs.moisture <= p["moisture"][1]):
        viol.append(f"moisture {obs.moisture}% outside {p['moisture']}")
    if not (p["rain"][0] <= obs.rain <= p["rain"][1]):
        viol.append(f"rain {obs.rain} mm/hr outside {p['rain']}")
    if obs.temp is not None and not (p["temp"][0] <= obs.temp <= p["temp"][1]):
        viol.append(f"temp {obs.temp} C outside {p['temp']}")
    return bool(viol), \
        {"moisture_pct": obs.moisture, "rain_mm_per_hr": obs.rain, "temp_c": obs.temp}, \
        {"moisture": p["moisture"], "rain": p["rain"], "temp": p["temp"]}, "; ".join(viol)


def _h_rate_of_change(engine, obs, p):
    ref = engine._ref_before(obs.ts - p["window_s"])
    if ref is None:
        return False, {"delta_pct": None, "has_history": False, "mitigated": False}, \
            {"max_pct_per_window": p["max_pct_per_window"], "window_s": p["window_s"]}, ""
    delta = obs.moisture - ref.moisture
    rain_active = obs.rain > p["rain_onset_gt"] or any(
        o.rain > p["rain_onset_gt"] for o in engine.history if ref.ts <= o.ts <= obs.ts)
    mitigated = delta > 0 and (rain_active or engine.valve_open)
    fired = abs(delta) > p["max_pct_per_window"] and not mitigated
    exp = (f"Soil moisture changed {delta:+.1f}% within {p['window_s']:.0f}s "
           f"(> {p['max_pct_per_window']}%/min) without rain/irrigation cause") if fired else ""
    return fired, {"delta_pct": round(delta, 2), "has_history": True, "mitigated": mitigated}, \
        {"max_pct_per_window": p["max_pct_per_window"], "window_s": p["window_s"]}, exp


def _h_command_effect(engine, obs, p):
    fired, exp, open_s, cmd_delta = False, "", None, None
    if (engine.valve_open and engine.valve_open_since is not None
            and (obs.ts - engine.valve_open_since) >= p["min_open_s"]):
        ref = engine._ref_before(engine.valve_open_since)
        if ref is not None:
            open_s = round(obs.ts - engine.valve_open_since, 1)
            cmd_delta = round(obs.moisture - ref.moisture, 2)
            if abs(cmd_delta) < p["min_delta_pct"]:
                fired = True
                exp = (f"Valve OPEN for {open_s}s but moisture moved "
                       f"{cmd_delta:+.2f}% (no physical effect)")
    return fired, {"valve_open": engine.valve_open, "open_s": open_s, "delta_pct": cmd_delta}, \
        {"min_open_s": p["min_open_s"], "min_delta_pct": p["min_delta_pct"]}, exp


def _h_stuck_replay(engine, obs, p):
    n = int(p["min_readings"])
    tail = list(engine.history)[-n:]
    dynamic = obs.rain > p["dynamic_rain_gt"] or engine.valve_open
    fired, exp = False, ""
    if len(tail) >= n and dynamic:
        vals = [o.moisture for o in tail]
        if (max(vals) - min(vals)) <= 1e-9:
            fired = True
            exp = (f"Soil moisture frozen at {vals[0]}% across {len(tail)} readings "
                   f"while environment dynamic (rain/valve): replay or stuck feed")
    return fired, {"readings": len(tail), "variance_zero": fired,
                   "environment_dynamic": bool(dynamic)}, {"min_readings": n}, exp


def _h_corroboration(engine, obs, p):
    fired = obs.rain > p["rain_gt"] and obs.moisture > p["moisture_gt"]
    exp = "Rainfall and soil moisture mutually consistent" if fired else ""
    return fired, {"rain_mm_per_hr": obs.rain, "moisture_pct": obs.moisture}, \
        {"rain_gt": p["rain_gt"], "moisture_gt": p["moisture_gt"]}, exp


HANDLERS = {
    "cross_sensor_conflict": _h_cross_sensor_conflict,
    "range_plausibility": _h_range_plausibility,
    "rate_of_change": _h_rate_of_change,
    "command_effect": _h_command_effect,
    "stuck_replay": _h_stuck_replay,
    "corroboration": _h_corroboration,
}


class IntegrityEngine:
    def __init__(self, rules=None, config=None) -> None:
        self.rules = rules if rules is not None else RULES
        self.cfg = config if config is not None else CONFIG
        self.history: deque[Observation] = deque(maxlen=int(self.cfg.get("history_max", 512)))
        self.valve_open = False
        self.valve_open_since: float | None = None

    def set_valve(self, open_: bool, ts: float | None = None) -> None:
        ts = _time.time() if ts is None else ts
        if open_ and not self.valve_open:
            self.valve_open_since = ts
        elif not open_:
            self.valve_open_since = None
        self.valve_open = open_

    def _ref_before(self, cutoff: float) -> Observation | None:
        for obs in reversed(self.history):
            if obs.ts <= cutoff:
                return obs
        return None

    def assess(self, obs: Observation) -> Evaluation:
        if obs.valve_open is not None:
            self.set_valve(obs.valve_open, obs.ts)
        self.history.append(obs)

        evidence: list[dict] = []
        fired: set[str] = set()
        penalty = bonus = 0

        for spec in self.rules:
            handler = HANDLERS.get(spec["type"])
            if handler is None:
                evidence.append({"rule_id": spec["id"], "name": spec["type"],
                                 "weight": spec["weight"], "fired": False,
                                 "inputs": {}, "threshold": {},
                                 "explanation": f"unknown rule type '{spec['type']}' - skipped"})
                continue
            is_fired, inputs, threshold, exp = handler(self, obs, spec.get("params") or {})
            w = spec["weight"]
            evidence.append({"rule_id": spec["id"], "name": spec["type"], "weight": w,
                             "fired": is_fired, "inputs": inputs,
                             "threshold": threshold, "explanation": exp})
            if is_fired:
                fired.add(spec["id"])
                if w > 0:
                    penalty += w
                else:
                    bonus += -w

        trust = max(0, min(100, 100 - penalty + bonus))
        if trust <= self.cfg.get("spoofed_at_or_below", 40):
            verdict, cmd, action = "SPOOFED", "CLOSE", "Irrigation valve auto-CLOSED (flood prevented)"
        elif trust <= self.cfg.get("degraded_at_or_below", 70):
            verdict, cmd, action = "DEGRADED", None, "Automated actuation HELD; operator review requested"
        else:
            verdict, cmd, action = "TRUSTED", None, "No action required"

        explanations = [e["explanation"] for e in evidence if e["fired"] and e["explanation"]]
        r6 = any(e["rule_id"] == "R6" and e["fired"] for e in evidence)
        reason = ("; ".join(explanations) if explanations
                  else ("Sensor readings consistent with rainfall" if r6
                        else "No environmental conflict detected"))

        return Evaluation(ts=obs.ts, trust_score=trust, verdict=verdict,
                          valve_command=cmd, action_taken=action, reason=reason,
                          fired_ids=sorted(fired), evidence=evidence)
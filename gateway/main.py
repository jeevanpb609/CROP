from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import FileResponse
import requests
import socket
import time
import os
import json
import threading
from collections import deque

# Import the Layer 3 Engine (v2.4.0 includes RULES_SOURCE)
from integrity_engine import IntegrityEngine, Observation, RULE_META, RULES_SOURCE

app = FastAPI(
    title="CROP Security Gateway",
    description="3-Layer Cyber Resilience & Data Integrity Gateway for Precision Agriculture",
    version="2.4.0 (Docker Testbed)",
)

# Container DNS names (must match container_name in docker-compose.yml)
SOIL_SENSOR = "http://crop_soil_sensor:8080"
WEATHER_STATION = "http://crop_weather_station:8080"
IRRIGATION_VALVE = "http://crop_irrigation_valve:8080"

DEVICE_TARGETS = {
    "soil_sensor": "crop_soil_sensor",
    "weather_station": "crop_weather_station",
    "irrigation_valve": "crop_irrigation_valve",
}

# Helper to handle trailing space bug in mock_device.py keys
def _get_val(d, key, default=None):
    if key in d: return d[key]
    if f"{key} " in d: return d[f"{key} "]
    return default

# ============ LAYER 2 CONFIG: Edge-IIoTset replay (v2.2.0) ============
TRACE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic_trace.json")
TRACE_DATA = None
TRACE_INDEX = 0
TRACE_LOCK = threading.Lock()

if os.path.exists(TRACE_FILE):
    try:
        with open(TRACE_FILE, "r", encoding="utf-8") as f:
            TRACE_DATA = json.load(f)
        print(f"[Layer 2] Edge-IIoTset trace loaded: {len(TRACE_DATA['sequence'])} replay windows")
    except Exception as e:
        print(f"[Layer 2] trace load failed ({e}); using simulated fallback")
else:
    print("[Layer 2] traffic_trace.json not found; using simulated fallback")

SIMULATED_NETWORK_PPS = [120, 135, 128, 142, 131, 12500, 13200, 14100, 140, 138, 125]
PPS_INDEX = 0
TRAFFIC_THRESHOLD = TRACE_DATA.get("threshold_pps", 500) if TRACE_DATA else 500
SUSTAINED_WINDOWS = TRACE_DATA.get("sustained_windows", 3) if TRACE_DATA else 3
PPS_HISTORY = deque(maxlen=SUSTAINED_WINDOWS)

# ============ LAYER 3 CONFIG: Integrity Engine (v2.4.0 YAML-driven) ============
ENGINE = IntegrityEngine()
print(f"[Layer 3] Integrity Engine initialized. Rule source: {RULES_SOURCE}")


class SpoofMode(BaseModel):
    spoof: bool


@app.get("/", include_in_schema=False)
def dashboard():
    """Serves the visual CROP dashboard."""
    return FileResponse(os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "index.html"))


@app.get("/api/info")
def root():
    return {
        "message": "CROP Security Gateway v2.4.0 (Docker Testbed)",
        "layers": [
            "Layer 1: Vulnerability Scanner",
            "Layer 2: Traffic Monitor (Edge-IIoTset replay)",
            "Layer 3: Data Integrity Engine (YAML-driven Rules)",
        ],
        "layer2_source": "Edge-IIoTset" if TRACE_DATA else "Simulated Array",
        "layer3_rules_source": RULES_SOURCE,
        "docs": "/docs",
    }


@app.get("/system/spoof-state")
def spoof_state():
    """Reports current spoof mode of the soil sensor."""
    try:
        return requests.get(f"{SOIL_SENSOR}/", timeout=3).json()
    except Exception as e:
        return {"error": str(e)}


# ============ LAYER 1: VULNERABILITY SCANNER (real Nmap + NVD API) ============
def nvd_cve_count(keyword: str) -> int:
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": 1},
            timeout=6,
        )
        if r.status_code == 200:
            return int(r.json().get("totalResults", 0))
    except Exception:
        pass
    return 0


@app.get("/layer1/scan/{device_name}")
def scan_device(device_name: str):
    if device_name not in DEVICE_TARGETS:
        raise HTTPException(status_code=404, detail=f"Unknown device '{device_name}'")
    host = DEVICE_TARGETS[device_name]
    open_ports = []
    services = []
    scan_mode = "nmap"
    try:
        import nmap
        ns = nmap.PortScanner()
        # python-nmap keys results by RESOLVED IP, not the hostname.
        ip = socket.gethostbyname(host)
        ns.scan(ip, "22,80,8080", arguments="-Pn")
        key = ip if ip in ns.all_hosts() else (ns.all_hosts()[0] if ns.all_hosts() else None)
        if key:
            for proto in ns[key].all_protocols():
                for port in ns[key][proto].keys():
                    if ns[key][proto][port]["state"] == "open":
                        open_ports.append(int(port))
                        services.append(ns[key][proto][port].get("name", ""))
    except Exception:
        pass
    if not open_ports:
        scan_mode = "socket-fallback"
        for port in (22, 80, 8080):
            s = socket.socket()
            s.settimeout(1)
            try:
                s.connect((host, port))
                open_ports.append(port)
                services.append("unknown")
            except Exception:
                pass
            finally:
                s.close()
    keyword = next((s for s in services if s and s != "unknown"), "http")
    cve_count = nvd_cve_count(keyword)
    risk_score = min(len(open_ports) * 30, 100)
    status = "CRITICAL" if risk_score >= 60 else "MEDIUM" if risk_score >= 30 else "LOW"
    return {
        "device": device_name,
        "target_host": host,
        "scan_mode": scan_mode,
        "open_ports": open_ports,
        "detected_services": services,
        "nvd_keyword": keyword,
        "nvd_keyword_cves": cve_count,
        "risk_score": risk_score,
        "status": status,
    }


# ============ LAYER 2: TRAFFIC MONITOR (v2.2.0 Edge-IIoTset replay) ============
def _next_window():
    global TRACE_INDEX, PPS_INDEX
    with TRACE_LOCK:
        if TRACE_DATA:
            seq = TRACE_DATA["sequence"]
            w = seq[TRACE_INDEX % len(seq)]
            TRACE_INDEX = (TRACE_INDEX + 1) % len(seq)
            return w["pps"], w["label"], w["segment"], "Edge-IIoTset"
        pps = SIMULATED_NETWORK_PPS[PPS_INDEX]
        PPS_INDEX = (PPS_INDEX + 1) % len(SIMULATED_NETWORK_PPS)
        label = "DDoS" if pps > TRAFFIC_THRESHOLD else "Normal"
        return pps, label, "simulated", "Simulated Array"


@app.get("/layer2/network-alerts")
def network_alerts(pps: int = None):
    if pps is None:
        pps, label, segment, source = _next_window()
    else:
        label = "DDoS" if pps > TRAFFIC_THRESHOLD else "Normal"
        segment, source = "manual-override", "manual"

    PPS_HISTORY.append(pps)
    sustained = (
        len(PPS_HISTORY) == PPS_HISTORY.maxlen
        and all(p > TRAFFIC_THRESHOLD for p in PPS_HISTORY)
    )
    is_alert = (pps > TRAFFIC_THRESHOLD) and sustained

    if is_alert:
        return {
            "status": "ALERT",
            "source": source,
            "data": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "alert_type": "DDoS SPIKE DETECTED",
                "current_pps": pps,
                "threshold": TRAFFIC_THRESHOLD,
                "severity": "CRITICAL",
                "attack_label": label,
                "segment": segment,
                "sustained_windows": len(PPS_HISTORY),
            },
        }
    return {
        "status": "NORMAL",
        "source": source,
        "data": {
            "current_pps": pps,
            "threshold": TRAFFIC_THRESHOLD,
            "message": "Traffic within normal parameters",
            "attack_label": label,
            "segment": segment,
            "sustained_windows": len(PPS_HISTORY),
        },
    }


@app.get("/layer2/provenance")
def layer2_provenance():
    if TRACE_DATA:
        return TRACE_DATA["provenance"]
    return {
        "dataset": "None — simulated fallback active",
        "note": "gateway/traffic_trace.json was not found at startup.",
    }


@app.post("/layer2/advance-traffic")
def advance_traffic():
    pps, label, segment, source = _next_window()
    return {"message": f"{source} window advanced", "current_pps": pps, "source": source}


# ============ LAYER 3: DATA INTEGRITY ENGINE (v2.4.0 YAML-driven) ============
@app.get("/layer3/trust-evaluation")
def evaluate_trust():
    try:
        soil = requests.get(f"{SOIL_SENSOR}/telemetry", timeout=3).json()
        weather = requests.get(f"{WEATHER_STATION}/telemetry", timeout=3).json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sensor fetch failed: {e}")
        
    moisture = _get_val(soil, "moisture_pct", -1.0)
    rain = _get_val(weather, "rain_mm_per_hr", 0.0)
    temp = _get_val(weather, "temp_c", None)
    
    # Create observation and assess using the formalized engine
    obs = Observation(
        ts=time.time(), 
        moisture=float(moisture), 
        rain=float(rain), 
        temp=float(temp) if temp is not None else None, 
        valve_open=ENGINE.valve_open
    )
    evaluation = ENGINE.assess(obs)
    
    action = evaluation.action_taken
    
    # Execute physical command if engine dictates
    if evaluation.valve_command == "CLOSE":
        try:
            requests.post(f"{IRRIGATION_VALVE}/actuate", json={"action": "CLOSE"}, timeout=3)
            ENGINE.set_valve(False, time.time())
        except Exception:
            action = "Valve close command failed"
            
    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "soil_sensor": soil,
        "weather_station": weather,
        "trust_score": evaluation.trust_score,
        "status": evaluation.verdict,
        "reason": evaluation.reason,
        "action_taken": action,
        "fired_ids": evaluation.fired_ids,
        "evidence": evaluation.evidence,
        "rules_source": RULES_SOURCE
    }


@app.get("/layer3/rules")
def get_rules():
    """Exposes the formalized rule set, weights, and source for the dashboard/paper."""
    return {"rules": RULE_META, "rules_source": RULES_SOURCE}


@app.post("/layer3/toggle-spoof")
def toggle_spoof(mode: SpoofMode):
    results = []
    for name, url in [
        ("soil_sensor", SOIL_SENSOR),
        ("weather_station", WEATHER_STATION),
        ("irrigation_valve", IRRIGATION_VALVE),
    ]:
        try:
            requests.post(f"{url}/set_spoof", json={"spoof": mode.spoof}, timeout=3)
            results.append({"device": name, "spoof_mode": mode.spoof, "status": "success"})
        except Exception as e:
            results.append({"device": name, "spoof_mode": mode.spoof, "status": f"failed: {e}"})
    return {"message": f"Spoof mode {'enabled' if mode.spoof else 'disabled'}", "results": results}
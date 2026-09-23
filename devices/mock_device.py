import os
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Agri-IoT Device Node")

# Docker passes these via environment variables in docker-compose.yml
DEVICE_TYPE = os.getenv("DEVICE_TYPE", "soil_sensor")
SPOOF = os.getenv("SPOOF", "true").lower() == "true"

VALVE_STATE = {"open": False}

class ActuatorCommand(BaseModel):
    action: str

class SpoofMode(BaseModel):
    spoof: bool

@app.get("/")
def get_info():
    return {"device_type": DEVICE_TYPE, "status": "online", "spoof_mode": SPOOF}

@app.post("/set_spoof")
def set_spoof(mode: SpoofMode):
    global SPOOF
    SPOOF = mode.spoof
    return {"device_type": DEVICE_TYPE, "spoof_mode": SPOOF}

@app.get("/telemetry")
def get_telemetry():
    if DEVICE_TYPE == "soil_sensor":
        if SPOOF:
            return {"moisture_pct": 0.0, "status": "bone_dry"}
        return {"moisture_pct": 62.0, "status": "moist"}
    if DEVICE_TYPE == "weather_station":
        if SPOOF:
            return {"rain_mm_per_hr": 45.0, "temp_c": 22.5}
        return {"rain_mm_per_hr": 0.0, "temp_c": 31.0}
    return {"status": "no telemetry available"}

@app.post("/actuate")
def control_actuator(cmd: ActuatorCommand):
    if DEVICE_TYPE != "irrigation_valve":
        return {"error": "Device is not an actuator"}
    if cmd.action.upper() == "OPEN":
        VALVE_STATE["open"] = True
    elif cmd.action.upper() == "CLOSE":
        VALVE_STATE["open"] = False
    else:
        return {"error": "Invalid action specification"}
    return {"valve_open": VALVE_STATE["open"], "message": f"Valve set to {cmd.action}"}
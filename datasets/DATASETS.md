# Datasets (not stored in this repository)

Raw captures exceed GitHub size limits and are redistributed by their authors.

**Edge-IIoTset** — Ferrag et al., 2022 (CC BY 4.0, academic use granted in perpetuity):
https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot

Files used by `tools/build_pps_trace.py`:

- `Normal traffic/Soil_Moisture/Soil_Moisture.csv` (~363 MB, 1,192,777 MQTT packets)
- `Attack traffic/DDoS_UDP_Flood_attack.pcap` (~200 MB, 3,215,732 packets)

Place them in `datasets/raw/`, then regenerate the replay trace:

    python tools/build_pps_trace.py

The committed `gateway/traffic_trace.json` is the **derived** 80-window
per-second PPS trace (30 s normal + 20 s flood + 30 s normal), so the gateway
runs out-of-the-box without downloading any dataset.

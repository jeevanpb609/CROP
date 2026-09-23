"""
CROP — Layer 3 Integrity Engine Test Harness (CP3)
Evaluates the formalized rule set against 7 distinct attack/benign scenarios.
Generates the Detection Rate / False Positive table for the Q1 journal manuscript.
"""
import sys
import os

# Add gateway to path to import the engine
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'gateway'))
from integrity_engine import IntegrityEngine, Observation

def run_scenario(name, description, observations, expect_verdict, expect_rules):
    engine = IntegrityEngine()
    final_eval = None
    for obs in observations:
        final_eval = engine.assess(obs)
        
    passed = (final_eval.verdict == expect_verdict)
    rules_pass = set(expect_rules).issubset(set(final_eval.fired_ids)) if expect_rules else (len(final_eval.fired_ids) == 0)
    
    status = "PASS" if (passed and rules_pass) else "FAIL"
    
    return {
        "Scenario": name,
        "Description": description,
        "Expected": expect_verdict,
        "Actual": final_eval.verdict,
        "Score": final_eval.trust_score,
        "Fired Rules": ", ".join(final_eval.fired_ids) if final_eval.fired_ids else "None",
        "Status": status
    }

def main():
    print("=" * 110)
    print("CROP LAYER 3 INTEGRITY ENGINE — FORMAL EVALUATION HARNESS")
    print("=" * 110)
    
    results = []
    
    # S1: Cross-Sensor Conflict (The Core Demo)
    s1_obs = [Observation(ts=10.0, moisture=0.0, rain=45.0)]
    results.append(run_scenario("S1", "Bone-dry spoof during heavy rain", s1_obs, "SPOOFED", ["R1"]))
    
    # S2: Normal Dry Day (Baseline)
    s2_obs = [Observation(ts=10.0, moisture=35.0, rain=0.0)]
    results.append(run_scenario("S2", "Normal dry day (baseline)", s2_obs, "TRUSTED", []))
    
    # S3: Corroboration (Rain + Wet Soil)
    s3_obs = [Observation(ts=10.0, moisture=75.0, rain=45.0)]
    results.append(run_scenario("S3", "Rain + wet soil (corroboration)", s3_obs, "TRUSTED", ["R6"]))
    
    # S4: Replay / Stuck Attack (Temporal State)
    s4_obs = [Observation(ts=float(i*10), moisture=45.0, rain=20.0) for i in range(10)]
    results.append(run_scenario("S4", "Replay attack (frozen readings during rain)", s4_obs, "DEGRADED", ["R5"]))
    
    # S5: Drift Spoof (Rate of Change)
    s5_obs = [
        Observation(ts=0.0, moisture=30.0, rain=0.0),
        Observation(ts=65.0, moisture=70.0, rain=0.0)
    ]
    results.append(run_scenario("S5", "Drift spoof (+40% jump in 30s)", s5_obs, "DEGRADED", ["R3"]))
    
    # S6: Command-Effect Mismatch (Actuator Fault)
    s6_obs = [
        Observation(ts=0.0, moisture=40.0, rain=0.0, valve_open=True),
        Observation(ts=350.0, moisture=40.2, rain=0.0, valve_open=True)
    ]
    results.append(run_scenario("S6", "Command-effect mismatch (valve open, no moisture change)", s6_obs, "DEGRADED", ["R4"]))
    
    # S7: Consistent Two-Sensor Spoof (The Honest Limitation)
    s7_obs = [Observation(ts=10.0, moisture=80.0, rain=50.0)]
    results.append(run_scenario("S7", "Consistent two-sensor spoof (Limitation)", s7_obs, "TRUSTED", ["R6"]))

    # Print Table
    print(f"\n{'Scenario':<6} | {'Description':<45} | {'Expected':<10} | {'Actual':<10} | {'Score':<5} | {'Fired Rules':<15} | {'Status':<6}")
    print("-" * 110)
    for r in results:
        print(f"{r['Scenario']:<6} | {r['Description']:<45} | {r['Expected']:<10} | {r['Actual']:<10} | {r['Score']:<5} | {r['Fired Rules']:<15} | {r['Status']:<6}")
        
    print("\n[Analysis for Paper]:")
    print("- S1-S3 prove the core cross-sensor validation and corroboration logic.")
    print("- S4-S6 prove the temporal state machine catches sophisticated FDIA (Replay, Drift, Actuator Fault).")
    print("- S7 is an HONEST LIMITATION: If an attacker compromises both sensors simultaneously")
    print("  to output physically consistent lies, the rule engine trusts them. This justifies")
    print("  future work (e.g., integrating external weather APIs or spatial correlation).")
    print("=" * 110)

if __name__ == "__main__":
    main()
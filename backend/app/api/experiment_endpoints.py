"""
Experiment visualization endpoints.
Serves pre-set POV/EXP accuracy data from a static JSON file
for thesis quantitative experiment display.
"""
import os
import json
from fastapi import APIRouter

router = APIRouter()

DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "experiment_data",
    "results.json",
)


def _load_data():
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@router.get("/experiment/scenarios")
def list_scenarios():
    data = _load_data()
    scenarios = [
        {
            "scenario_id": s["scenario_id"],
            "component": s["component"],
            "version": s["version"],
            "category": s["category"],
        }
        for s in data["scenarios"]
    ]
    return {"status": "success", "data": scenarios}


@router.get("/experiment/results")
def get_results():
    data = _load_data()
    return {"status": "success", "data": data["scenarios"]}


@router.get("/experiment/stats")
def get_stats():
    data = _load_data()
    scenarios = data["scenarios"]

    pov_success = sum(sum(s["pov_results"]) for s in scenarios)
    pov_total = sum(len(s["pov_results"]) for s in scenarios)
    exp_success = sum(sum(s["exp_results"]) for s in scenarios)
    exp_total = sum(len(s["exp_results"]) for s in scenarios)

    # --- per-category ---
    cats: dict = {}
    for s in scenarios:
        cat = s["category"]
        if cat not in cats:
            cats[cat] = {"pov_s": 0, "pov_t": 0, "exp_s": 0, "exp_t": 0}
        cats[cat]["pov_s"] += sum(s["pov_results"])
        cats[cat]["pov_t"] += len(s["pov_results"])
        cats[cat]["exp_s"] += sum(s["exp_results"])
        cats[cat]["exp_t"] += len(s["exp_results"])

    by_category = {
        cat: {
            "pov_success": v["pov_s"],
            "pov_total": v["pov_t"],
            "pov_rate": round(v["pov_s"] / v["pov_t"], 4) if v["pov_t"] else 0,
            "exp_success": v["exp_s"],
            "exp_total": v["exp_t"],
            "exp_rate": round(v["exp_s"] / v["exp_t"], 4) if v["exp_t"] else 0,
        }
        for cat, v in cats.items()
    }

    # --- per-scenario ---
    by_scenario = []
    for s in scenarios:
        pt = len(s["pov_results"])
        ps = sum(s["pov_results"])
        et = len(s["exp_results"])
        es = sum(s["exp_results"])
        by_scenario.append(
            {
                "scenario_id": s["scenario_id"],
                "component": s["component"],
                "version": s["version"],
                "category": s["category"],
                "pov_results": s["pov_results"],
                "exp_results": s["exp_results"],
                "pov_success": ps,
                "pov_total": pt,
                "pov_rate": round(ps / pt, 4) if pt else 0,
                "exp_success": es,
                "exp_total": et,
                "exp_rate": round(es / et, 4) if et else 0,
            }
        )

    return {
        "status": "success",
        "data": {
            "pov_overall": {
                "success": pov_success,
                "total": pov_total,
                "rate": round(pov_success / pov_total, 4) if pov_total else 0,
            },
            "exp_overall": {
                "success": exp_success,
                "total": exp_total,
                "rate": round(exp_success / exp_total, 4) if exp_total else 0,
            },
            "scenario_count": len(scenarios),
            "total_runs": pov_total + exp_total,
            "by_category": by_category,
            "by_scenario": by_scenario,
        },
    }

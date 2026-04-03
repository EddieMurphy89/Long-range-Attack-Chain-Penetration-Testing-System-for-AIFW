import os
import json
from typing import Any, Dict, List, Optional
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


def _normalize_text(value: Optional[str]) -> str:
    if not value:
        return ""
    return "".join(str(value).lower().split())


def _build_query_key(component: str, version: str) -> str:
    return f"{component}@{version}"


def _collect_metric(results: List[bool]) -> Dict[str, Any]:
    total = len(results)
    success = sum(results)
    return {
        "results": results,
        "success": success,
        "total": total,
        "rate": round(success / total, 4) if total else 0,
    }


def _format_scenario_stats(scenario: Dict[str, Any]) -> Dict[str, Any]:
    pov = _collect_metric(scenario.get("pov_results", []))
    exp = _collect_metric(scenario.get("exp_results", []))
    bypass = _collect_metric(scenario.get("aifw_bypass_results", []))

    return {
        "scenario_id": scenario["scenario_id"],
        "component": scenario["component"],
        "version": scenario["version"],
        "query_key": _build_query_key(scenario["component"], scenario["version"]),
        "category": scenario["category"],
        "chain_length": scenario.get("chain_length"),
        "attack_goal": scenario.get("attack_goal"),
        "pov_builder": scenario.get("pov_builder"),
        "exp_builder": scenario.get("exp_builder"),
        "aifw_bypass_strategy": scenario.get("aifw_bypass_strategy"),
        "pov_results": pov["results"],
        "exp_results": exp["results"],
        "aifw_bypass_results": bypass["results"],
        "pov_success": pov["success"],
        "pov_total": pov["total"],
        "pov_rate": pov["rate"],
        "exp_success": exp["success"],
        "exp_total": exp["total"],
        "exp_rate": exp["rate"],
        "aifw_bypass_success": bypass["success"],
        "aifw_bypass_total": bypass["total"],
        "aifw_bypass_rate": bypass["rate"],
    }


def _build_suggestions(scenarios: List[Dict[str, Any]], query_key: str) -> List[str]:
    normalized_query = _normalize_text(query_key)
    suggestions: List[str] = []
    for scenario in scenarios:
        scenario_key = _build_query_key(scenario["component"], scenario["version"])
        haystacks = (
            _normalize_text(scenario_key),
            _normalize_text(scenario["component"]),
            _normalize_text(scenario["version"]),
            _normalize_text(scenario["scenario_id"]),
        )
        if any(normalized_query and normalized_query in item for item in haystacks):
            suggestions.append(scenario_key)
    return suggestions[:5]


@router.get("/experiment/scenarios")
def list_scenarios():
    data = _load_data()
    scenarios = [
        {
            "scenario_id": s["scenario_id"],
            "component": s["component"],
            "version": s["version"],
            "query_key": _build_query_key(s["component"], s["version"]),
            "category": s["category"],
        }
        for s in data["scenarios"]
    ]
    return {"status": "success", "data": scenarios}


@router.get("/experiment/results")
def get_results():
    data = _load_data()
    return {
        "status": "success",
        "data": [_format_scenario_stats(s) for s in data["scenarios"]],
    }


@router.get("/experiment/lookup")
def lookup_result(query_key: str):
    data = _load_data()
    scenarios = data["scenarios"]
    normalized_query = _normalize_text(query_key)

    for scenario in scenarios:
        query_candidates = {
            _normalize_text(_build_query_key(scenario["component"], scenario["version"])),
            _normalize_text(f"{scenario['component']}/{scenario['version']}"),
            _normalize_text(f"{scenario['component']} {scenario['version']}"),
        }
        if normalized_query in query_candidates:
            return {
                "status": "success",
                "found": True,
                "query_key": _build_query_key(scenario["component"], scenario["version"]),
                "data": _format_scenario_stats(scenario),
                "suggestions": [],
            }

    return {
        "status": "success",
        "found": False,
        "query_key": query_key,
        "data": None,
        "suggestions": _build_suggestions(scenarios, query_key),
    }


@router.get("/experiment/stats")
def get_stats():
    data = _load_data()
    scenarios = data["scenarios"]

    pov_success = sum(sum(s["pov_results"]) for s in scenarios)
    pov_total = sum(len(s["pov_results"]) for s in scenarios)
    exp_success = sum(sum(s["exp_results"]) for s in scenarios)
    exp_total = sum(len(s["exp_results"]) for s in scenarios)
    bypass_success = sum(sum(s.get("aifw_bypass_results", [])) for s in scenarios)
    bypass_total = sum(len(s.get("aifw_bypass_results", [])) for s in scenarios)

    # --- per-category ---
    cats: dict = {}
    for s in scenarios:
        cat = s["category"]
        if cat not in cats:
            cats[cat] = {
                "pov_s": 0,
                "pov_t": 0,
                "exp_s": 0,
                "exp_t": 0,
                "bypass_s": 0,
                "bypass_t": 0,
            }
        cats[cat]["pov_s"] += sum(s["pov_results"])
        cats[cat]["pov_t"] += len(s["pov_results"])
        cats[cat]["exp_s"] += sum(s["exp_results"])
        cats[cat]["exp_t"] += len(s["exp_results"])
        cats[cat]["bypass_s"] += sum(s.get("aifw_bypass_results", []))
        cats[cat]["bypass_t"] += len(s.get("aifw_bypass_results", []))

    by_category = {
        cat: {
            "pov_success": v["pov_s"],
            "pov_total": v["pov_t"],
            "pov_rate": round(v["pov_s"] / v["pov_t"], 4) if v["pov_t"] else 0,
            "exp_success": v["exp_s"],
            "exp_total": v["exp_t"],
            "exp_rate": round(v["exp_s"] / v["exp_t"], 4) if v["exp_t"] else 0,
            "aifw_bypass_success": v["bypass_s"],
            "aifw_bypass_total": v["bypass_t"],
            "aifw_bypass_rate": round(v["bypass_s"] / v["bypass_t"], 4) if v["bypass_t"] else 0,
        }
        for cat, v in cats.items()
    }

    # --- per-scenario ---
    by_scenario = [_format_scenario_stats(s) for s in scenarios]

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
            "aifw_bypass_overall": {
                "success": bypass_success,
                "total": bypass_total,
                "rate": round(bypass_success / bypass_total, 4) if bypass_total else 0,
            },
            "scenario_count": len(scenarios),
            "total_runs": pov_total + exp_total + bypass_total,
            "by_category": by_category,
            "by_scenario": by_scenario,
        },
    }

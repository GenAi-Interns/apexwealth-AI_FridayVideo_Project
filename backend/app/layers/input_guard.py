"""
input_guard.py
────────────────────────────────────────────────────────────
Layer 1 — Input Guard

Responsibilities:
  1. Run the Hybrid Evaluator for fast local risk scoring
  2. Apply static + dynamic blocked pattern matching
  3. Return a structured InputGuardResult used by main.py
     to decide whether to fast-track, escalate, or block immediately
"""

import logging
from dataclasses import dataclass
from app.services.logger import client
from app.layers.hybrid_evaluator import evaluate, HybridResult

logger = logging.getLogger("SecureShield.InputGuard")


@dataclass
class InputGuardResult:
    passed: bool                   # False → hard block regardless of scores
    hybrid: HybridResult           # Full hybrid eval (score, decision, reasoning)
    blocked_by_pattern: bool = False
    matched_static_pattern: str = ""


async def run_input_guard(
    text: str,
    user_role: str = "Employee",
    user_department: str = "",
) -> InputGuardResult:
    """
    Main entry point for Layer 1.
    Returns an InputGuardResult with hybrid scoring + hard-block flag.
    """

    # ── Step 1: Local Hybrid Evaluation (always fast, no network) ────────────
    hybrid = evaluate(text, user_role=user_role, user_department=user_department)

    # ── Step 2: Static Fallback Blocked Patterns ─────────────────────────────
    # These are additional patterns not yet in safety_knowledge.json.
    # They guarantee a hard block regardless of hybrid score.
    static_blocked = [
        "hack", "attack", "bypass", "ignore previous", "ignore instructions",
        "forget all previous", "system prompt", "developer mode", "jailbreak",
        "dan mode", "act as", "disregard instructions", "reveal secret",
    ]

    # ── Step 3: Dynamic Rules from MongoDB ───────────────────────────────────
    try:
        rules_cursor = client["SSA_Security"]["security_rules"].find(
            {"type": "blocked_pattern"}
        )
        dynamic_rules = await rules_cursor.to_list(length=100)
        for rule in dynamic_rules:
            pattern = rule.get("pattern")
            if pattern and pattern.lower() not in static_blocked:
                static_blocked.append(pattern.lower())
    except Exception as e:
        logger.warning(f"Could not load dynamic rules from MongoDB: {e}")

    # ── Step 4: Pattern Match Check ───────────────────────────────────────────
    matched_pattern = ""
    for pattern in static_blocked:
        if pattern in text.lower():
            matched_pattern = pattern
            logger.warning(
                f"INPUT_GUARD HARD BLOCK — static pattern matched: '{pattern}'"
            )
            return InputGuardResult(
                passed=False,
                hybrid=hybrid,
                blocked_by_pattern=True,
                matched_static_pattern=pattern,
            )

    # ── Step 5: Respect Hybrid Immediate Block ────────────────────────────────
    if hybrid.decision == "IMMEDIATE_BLOCK":
        logger.warning(
            f"INPUT_GUARD HYBRID BLOCK — score={hybrid.local_risk_score} "
            f"threats={hybrid.matched_threats}"
        )
        return InputGuardResult(
            passed=False,
            hybrid=hybrid,
            blocked_by_pattern=False,
        )

    # ── All checks passed — forward hybrid result for downstream decisions ────
    return InputGuardResult(passed=True, hybrid=hybrid)


# ── Legacy shim — keeps old callers working (used in test scripts) ────────────
async def check_input(text: str) -> bool:
    """Legacy wrapper — returns simple bool. Use run_input_guard() for full detail."""
    result = await run_input_guard(text)
    return result.passed
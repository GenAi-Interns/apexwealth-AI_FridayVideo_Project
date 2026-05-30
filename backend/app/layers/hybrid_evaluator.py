"""
hybrid_evaluator.py
────────────────────────────────────────────────────────────
SecureShield Hybrid Security Evaluator

Combines three local signals into a single Risk Score (0.0 – 1.0):
  1. Regex / keyword threat matching  (safety_knowledge.json)
  2. RBAC policy alignment check
  3. Intent classification (conversational vs administrative vs hostile)

Risk Score → Pipeline Decision
  < 0.15  →  FAST_TRACK_ALLOW  (skip cloud AI guards entirely)
  0.15–0.75 →  ESCALATE         (send to Toxicity + Semantic AI judges)
  > 0.75  →  IMMEDIATE_BLOCK   (no cloud API call needed)

Returns a HybridResult dataclass consumed by main.py.
"""

import json
import os
import re
import logging
from dataclasses import dataclass, field
from typing import List, Tuple

logger = logging.getLogger("SecureShield.HybridEvaluator")

# ── Load local Knowledge Base ────────────────────────────────────────────────
_KB_PATH = os.path.join(os.path.dirname(__file__), "safety_knowledge.json")

def _load_kb() -> dict:
    try:
        with open(_KB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load safety_knowledge.json: {e}")
        return {}

_KB: dict = _load_kb()

THRESHOLDS: dict = _KB.get("thresholds", {
    "fast_track_allow": 0.15,
    "escalate_to_ai":   0.50,
    "immediate_block":  0.75,
})
RISK_WEIGHTS: dict = _KB.get("risk_weights", {
    "prompt_injection":   0.90,
    "data_exfiltration":  0.85,
    "system_abuse":       0.95,
    "social_engineering": 0.75,
})

# ── Result Model ─────────────────────────────────────────────────────────────
@dataclass
class HybridResult:
    local_risk_score: float = 0.0          # 0.0 – 1.0 from local checks
    decision: str = "ESCALATE"             # FAST_TRACK_ALLOW | ESCALATE | IMMEDIATE_BLOCK
    matched_threats: List[str] = field(default_factory=list)   # threat category names
    matched_patterns: List[str] = field(default_factory=list)  # exact phrases matched
    intent_class: str = "UNKNOWN"          # GREETING | CONVERSATIONAL | ADMINISTRATIVE | HOSTILE
    reasoning: str = ""                    # human-readable explanation
    is_safe_greeting: bool = False

# ── 1. Threat Signal Scanner ─────────────────────────────────────────────────
def _scan_threats(text: str) -> Tuple[float, List[str], List[str]]:
    """
    Scans the normalized text against all threat_signals categories.
    Returns (max_risk_score, [threat_categories], [matched_phrases]).
    """
    threat_signals: dict = _KB.get("threat_signals", {})
    matched_threats: List[str] = []
    matched_patterns: List[str] = []
    max_score: float = 0.0

    for category, patterns in threat_signals.items():
        weight = RISK_WEIGHTS.get(category, 0.70)
        for phrase in patterns:
            # Use word-boundary-aware matching for short phrases
            escaped = re.escape(phrase.lower())
            if re.search(rf"\b{escaped}\b", text, re.IGNORECASE):
                if category not in matched_threats:
                    matched_threats.append(category)
                if phrase not in matched_patterns:
                    matched_patterns.append(phrase)
                # Take the highest weight from matched categories
                if weight > max_score:
                    max_score = weight

    return max_score, matched_threats, matched_patterns


# ── 2. Intent Classifier ─────────────────────────────────────────────────────
def _classify_intent(text: str) -> Tuple[str, float]:
    """
    Classifies the message intent based on content patterns.
    Returns (intent_class, intent_risk_penalty).
    """
    lower = text.lower().strip()

    # Greeting check — exact or startswith match for very short inputs
    greetings: list = _KB.get("safe_greetings", [])
    if lower in greetings or any(lower.startswith(g) for g in greetings if len(g) > 2):
        return "GREETING", 0.0

    # Check word count — very short messages are likely greetings missed above
    words = lower.split()
    if len(words) <= 3:
        # If it has no threat patterns and is very short → treat as conversational
        return "CONVERSATIONAL", 0.0

    # Conversational pattern check
    conv_patterns: list = _KB.get("safe_conversational_patterns", [])
    for pattern in conv_patterns:
        if lower.startswith(pattern) or f" {pattern} " in f" {lower} ":
            return "CONVERSATIONAL", 0.0

    # Administrative check — longer queries without threat signals
    admin_keywords = [
        "report", "dashboard", "metrics", "logs", "analytics",
        "status", "system", "access", "configure", "setting"
    ]
    if any(kw in lower for kw in admin_keywords):
        return "ADMINISTRATIVE", 0.10   # Small risk bump for admin queries

    return "UNKNOWN", 0.05


# ── 3. RBAC Quick Check ──────────────────────────────────────────────────────
def _rbac_risk(text: str, user_role: str, user_department: str) -> float:
    """
    Fast keyword-based RBAC mismatch scorer.
    Returns a partial risk score (0.0 – 0.80) based on role/dept misalignment.
    """
    if not user_role or user_role == "Admin":
        return 0.0

    lower = text.lower()

    # Restricted keywords only for HR
    hr_keywords = [
        "employee data", "salary", "payroll", "performance review",
        "compensation", "wages", "worker info", "hr records",
        "paycheck", "bonus"
    ]
    if any(kw in lower for kw in hr_keywords):
        if user_department != "HR":
            return 0.80   # Definitive RBAC violation — should block!

    # Employee restricted keywords
    if user_role == "Employee":
        restricted = [
            "confidential", "financial report", "strategy",
            "admin panel", "secret", "proprietary",
            "internal docs", "earnings call"
        ]
        if any(kw in lower for kw in restricted):
            return 0.80   # Definitive RBAC violation — should block!

    return 0.0


# ── Main Public Interface ─────────────────────────────────────────────────────
def evaluate(
    text: str,
    user_role: str = "Employee",
    user_department: str = "",
) -> HybridResult:
    """
    Run the full local hybrid evaluation on a normalized input.
    Returns a HybridResult containing the local risk score and decision.
    """
    result = HybridResult()

    # 1. Threat signal scan
    threat_score, matched_threats, matched_patterns = _scan_threats(text)
    result.matched_threats  = matched_threats
    result.matched_patterns = matched_patterns

    # 2. Intent classification
    intent_class, intent_penalty = _classify_intent(text)
    result.intent_class = intent_class

    if intent_class == "GREETING":
        result.is_safe_greeting = True

    # 3. RBAC risk contribution
    rbac_score = _rbac_risk(text, user_role, user_department)

    # 4. Global Local Risk Score  (threats dominate; RBAC and intent adjust)
    if threat_score > 0:
        # Threat found — don't let greeting/intent deflate a real threat score
        raw_score = threat_score + (rbac_score * 0.20) + (intent_penalty * 0.10)
    elif rbac_score > 0:
        # RBAC violation, no direct threat patterns
        raw_score = rbac_score + (intent_penalty * 0.10)
    else:
        # No threat signals at all
        raw_score = intent_penalty

    result.local_risk_score = min(round(raw_score, 4), 1.0)

    # 5. Decision routing
    if result.local_risk_score < THRESHOLDS["fast_track_allow"]:
        result.decision = "FAST_TRACK_ALLOW"
    elif result.local_risk_score >= THRESHOLDS["immediate_block"]:
        result.decision = "IMMEDIATE_BLOCK"
    else:
        result.decision = "ESCALATE"

    # 6. Human-readable reasoning
    parts = []
    if result.is_safe_greeting:
        parts.append(f"Identified as safe greeting (intent={intent_class})")
    if matched_threats:
        parts.append(f"Threat signals detected: {', '.join(matched_threats)} "
                     f"(patterns: {', '.join(matched_patterns[:3])})")
    if rbac_score > 0:
        parts.append(f"RBAC mismatch detected (role={user_role}, dept={user_department})")
    if not parts:
        parts.append(f"No threats found, intent classified as {intent_class}")

    result.reasoning = " | ".join(parts)

    logger.debug(
        f"HybridEval: score={result.local_risk_score} decision={result.decision} "
        f"intent={result.intent_class} threats={result.matched_threats}"
    )

    return result

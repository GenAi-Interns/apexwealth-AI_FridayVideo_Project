"""
toxicity_guard.py
────────────────────────────────────────────────────────────
Layer 3 — Toxicity Guard (LLM-as-a-Judge)

Responsibilities:
  1. Classify toxicity using a cloud LLM with structured JSON output
  2. Return a ToxicityResult with score, reasoning chain, and categories
  3. Graceful fallback — if API is unavailable, use local heuristic instead
     of a blind fail-secure block (prevents false positives like "hii")
"""

import re
import logging
from typing import Dict, Optional
from pydantic import BaseModel, Field
import instructor
from openai import AsyncOpenAI

from app.config import settings

logger = logging.getLogger("SecureShield.ToxicityGuard")


# ── Output Schema ─────────────────────────────────────────────────────────────
class ToxicityReport(BaseModel):
    is_toxic: bool = Field(
        description="True if content exceeds toxicity thresholds"
    )
    score: float = Field(
        description="Overall toxicity score from 0.0 (safe) to 1.0 (extremely toxic)"
    )
    reasoning_chain: str = Field(
        description=(
            "Step-by-step logical reasoning explaining how you reached this classification. "
            "Start with what the message is about, then evaluate each toxicity category, "
            "then state your final decision."
        )
    )
    reason: str = Field(
        description="Brief one-sentence summary of the classification result"
    )
    categories: Dict[str, float] = Field(
        description="Per-category scores (Hate, Harassment, Threat, Self-harm, Sexual) 0.0–1.0"
    )


# ── Result Model returned to main.py ─────────────────────────────────────────
class ToxicityResult:
    def __init__(
        self,
        passed: bool,
        score: float,
        reasoning_chain: str,
        reason: str,
        categories: dict,
        used_fallback: bool = False,
    ):
        self.passed = passed
        self.score = score
        self.reasoning_chain = reasoning_chain
        self.reason = reason
        self.categories = categories
        self.used_fallback = used_fallback   # True when API was unavailable


# ── LLM Client (singleton) ────────────────────────────────────────────────────
class ToxicityEngine:
    _client = None
    _model: str = settings.GUARD_MODEL

    @classmethod
    def get_client_and_model(cls):
        if cls._client is None:
            api_key  = settings.OPENROUTER_API_KEY
            base_url = "https://openrouter.ai/api/v1"
            cls._model = settings.GUARD_MODEL

            if api_key.startswith("AIzaSy"):
                base_url  = "https://generativelanguage.googleapis.com/v1beta/openai/"
                cls._model = "gemini-2.5-flash"

            cls._client = instructor.from_openai(
                AsyncOpenAI(base_url=base_url, api_key=api_key, timeout=30.0),
                mode=instructor.Mode.JSON,
            )
        return cls._client, cls._model


# ── Local Fallback Heuristic ──────────────────────────────────────────────────
_TOXIC_KEYWORDS = [
    "kill", "murder", "hate", "die", "racist", "sexist", "slur",
    "attack", "bomb", "suicide", "harm", "abuse", "harass", "threat",
    "idiot", "stupid", "moron", "dumb", "loser", "pathetic",
]

def _local_toxicity_check(text: str) -> ToxicityResult:
    """
    Lightweight local heuristic used when the cloud API is unreachable.
    Prevents safe greetings from being blocked due to API failures.
    """
    lower = text.lower()
    words = lower.split()

    # Very short / simple messages — almost certainly safe
    if len(words) <= 5 and not any(kw in lower for kw in _TOXIC_KEYWORDS):
        return ToxicityResult(
            passed=True,
            score=0.02,
            reasoning_chain=(
                "Fallback mode (API unavailable). Message is very short and contains no "
                "known toxic keywords. Classified as safe by local heuristic."
            ),
            reason="Short message with no toxic indicators — locally approved.",
            categories={
                "Hate": 0.0, "Harassment": 0.0,
                "Threat": 0.0, "Self-harm": 0.0, "Sexual": 0.0
            },
            used_fallback=True,
        )

    matched = [kw for kw in _TOXIC_KEYWORDS if re.search(rf"\b{re.escape(kw)}\b", lower)]
    hit_count = len(matched)

    if hit_count == 0:
        score = 0.10
        passed = True
        reason = "No toxic keywords found — locally approved via fallback."
    elif hit_count <= 2:
        score = 0.45
        passed = True   # WARN range, not block
        reason = f"Minor toxic signals detected ({', '.join(matched)}) — passed with warning."
    else:
        score = 0.85
        passed = False
        reason = f"Multiple toxic keywords detected ({', '.join(matched)}) — blocked by fallback."

    return ToxicityResult(
        passed=passed,
        score=score,
        reasoning_chain=(
            f"Fallback mode (API unavailable). Scanned {len(words)} words. "
            f"Found {hit_count} toxic keyword(s): {matched}. Score={score}."
        ),
        reason=reason,
        categories={
            "Hate": min(hit_count * 0.15, 1.0),
            "Harassment": min(hit_count * 0.12, 1.0),
            "Threat": 0.0, "Self-harm": 0.0, "Sexual": 0.0
        },
        used_fallback=True,
    )


# ── Main Check ────────────────────────────────────────────────────────────────
async def check_toxicity(text: str) -> ToxicityResult:
    """
    Analyzes text for toxicity using LLM-as-a-Judge.
    Returns ToxicityResult (passed=True means SAFE).
    Falls back gracefully to local heuristic on API failure.
    """
    client, model = ToxicityEngine.get_client_and_model()

    try:
        report: ToxicityReport = await client.chat.completions.create(
            model=model,
            response_model=ToxicityReport,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a Content Safety Classifier for an Enterprise AI Gateway.\n\n"
                        "IMPORTANT INSTRUCTIONS:\n"
                        "1. Simple greetings (hi, hello, hii, hey, thanks, okay, etc.) "
                        "are ALWAYS safe — score them 0.0 across all categories.\n"
                        "2. Conversational questions and work-related queries are safe.\n"
                        "3. Only flag content that contains genuine hate speech, harassment, "
                        "explicit threats, self-harm encouragement, or sexual content.\n\n"
                        "REASONING PROTOCOL:\n"
                        "Step 1 — Describe what the message is about.\n"
                        "Step 2 — Evaluate each category: Hate, Harassment, Threat, "
                        "Self-harm, Sexual (score 0.0–1.0 each).\n"
                        "Step 3 — Compute an overall score and state is_toxic=true only "
                        "if overall score > 0.7 OR any single category > 0.8.\n"
                        "Step 4 — Write a brief reason summarizing your decision."
                    ),
                },
                {"role": "user", "content": text},
            ],
        )

        passed = not report.is_toxic
        if not passed:
            logger.warning(
                f"TOXICITY BLOCKED — score={report.score:.2f} reason='{report.reason}'"
            )

        return ToxicityResult(
            passed=passed,
            score=report.score,
            reasoning_chain=report.reasoning_chain,
            reason=report.reason,
            categories=report.categories,
            used_fallback=False,
        )

    except Exception as e:
        logger.error(f"Toxicity API error — activating local fallback: {e}")
        return _local_toxicity_check(text)

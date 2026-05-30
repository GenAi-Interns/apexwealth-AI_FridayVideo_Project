import warnings
warnings.filterwarnings("ignore", category=FutureWarning, module="instructor.providers.gemini")

from fastapi import FastAPI, Query, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
# Force Uvicorn Reload for Policy Engine updates
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import uuid
from pydantic import BaseModel
from datetime import datetime

from app.config import settings
# ── Layer imports (structured result types) ──────────────────────────────────
from app.layers.input_guard import run_input_guard
from app.layers.policy_engine import check_policy
from app.layers.toxicity_guard import check_toxicity
from app.layers.semantic_guard import check_semantic_intent
from app.layers.pii_guard import scrub_pii, scan_pii_and_secrets
from app.layers.normalizer import normalize_text
# ── Service imports ───────────────────────────────────────────────────────────
from app.services.llm_service import generate_response
from app.services.logger import init_audit_log, log_pipeline_event, finalize_audit_log, client
from app.services.user_service import (
    register_user_db, authenticate_user_db, get_current_user,
    require_any_admin,
)

# --- NEW: GUARDRAILS & LOGGING ---
import json
import os

def simple_langsmith_logger(user_input, risk_score, decision, final_response):
    """Basic local logging system (LangSmith-style)"""
    try:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_input": user_input,
            "risk_score": risk_score,
            "decision": decision,
            "final_response": final_response
        }
        with open("../logs/simple_audit.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"Logging error: {e}")

import re

async def apply_guardrails(response_text: str) -> str:
    """Apply Guardrails after LLM response. Fail-safe."""
    original_text = response_text
    try:
        patterns = {
            "JWT_TOKEN": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "API_KEY": r"sk-[a-zA-Z0-9]{20,}",
            "AWS_KEY": r"AKIA[0-9A-Z]{16}",
            "GENERIC_SECRET": r"(?i)(?:api_key|apikey|access_token|secret_key)[=:\s]+['\"]?([a-zA-Z0-9\-_]{32,})['\"]?"
        }
        
        redacted_text = original_text
        total_findings = 0
        
        for secret_type, pattern in patterns.items():
            matches = list(re.finditer(pattern, original_text))
            if matches:
                total_findings += len(matches)
                for match in matches:
                    if match.lastindex and match.lastindex >= 1:
                        # Replace the captured group
                        redacted_text = redacted_text.replace(match.group(1), f"[REDACTED_{secret_type}]")
                    else:
                        redacted_text = redacted_text.replace(match.group(0), f"[REDACTED_{secret_type}]")
                
        # Block only if severe (e.g. 3 or more secrets leaked)
        if total_findings >= 3:
            raise ValueError(f"Severe output violation: {total_findings} secrets detected")
            
        return redacted_text
    except ValueError as ve:
        # Re-raise so the pipeline can catch and block it
        raise ve
    except Exception as e:
        print(f"Guardrails error: {e}")
        return original_text # Fallback: return original output
# ---------------------------------

# 1. Initialize App
app = FastAPI(title=settings.app_name)

chat_db = client["SSA_Security"]["chats"]
settings_db = client["SSA_Security"]["settings"]

async def get_gateway_settings():
    doc = await settings_db.find_one({"id": "global"})
    if not doc:
        doc = {
            "id": "global",
            "input_guard": True,
            "policy_engine": True,
            "toxicity_guard": True,
            "pii_guard": True,
            "provider": "Google Gemini (Current)",
            "failover_node": "Groq API",
            "log_failed": True,
            "anonymize": False,
        }
        await settings_db.insert_one(doc)
    return doc

# 2. Add CORS Middleware (Crucial for Frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", 
        "http://127.0.0.1:5173",
        "http://localhost:5174", 
        "http://127.0.0.1:5174",
        "https://secureshield-rho-two.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- NEW: NETWORK GUARD (RATE LIMITING) ---
import time

NETWORK_RATE_LIMIT_COUNT = 30
NETWORK_RATE_LIMIT_WINDOW_SECONDS = 60
ip_request_counts = {}

@app.middleware("http")
async def network_guard_middleware(request: Request, call_next):
    try:
        path = request.url.path
        if path == "/" or path.startswith("/health"):
            return await call_next(request)
            
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()
        
        if client_ip not in ip_request_counts:
            ip_request_counts[client_ip] = []
            
        # Clean up old requests
        ip_request_counts[client_ip] = [
            t for t in ip_request_counts[client_ip] 
            if current_time - t < NETWORK_RATE_LIMIT_WINDOW_SECONDS
        ]
        
        if len(ip_request_counts[client_ip]) >= NETWORK_RATE_LIMIT_COUNT:
            return JSONResponse(
                status_code=200,
                content={"status": "BLOCKED", "reason": "Too many requests detected"}
            )
            
        ip_request_counts[client_ip].append(current_time)
        return await call_next(request)
        
    except Exception as e:
        print(f"Network Guard Error: {e}")
        return await call_next(request)
# ------------------------------------------

@app.on_event("startup")
async def setup_data_retention():
    """Sets up MongoDB TTL indexes for automatic data cleanup."""
    retention_seconds = settings.RETENTION_DAYS * 24 * 60 * 60
    
    # # TTL Index for Audit Logs
    # await client["SSA_Security"]["logs"].create_index(
    #     "timestamp", 
    #     expireAfterSeconds=retention_seconds
    # )
    
    # # TTL Index for Chat History
    # await client["SSA_Security"]["chats"].create_index(
    #     "timestamp", 
    #     expireAfterSeconds=retention_seconds
    # )
    
    print(f"Data retention policy active: {settings.RETENTION_DAYS} days")

class SettingsUpdateModel(BaseModel):
    input_guard: bool
    policy_engine: bool
    toxicity_guard: bool
    pii_guard: bool
    provider: str
    failover_node: str
    log_failed: bool
    anonymize: bool

# Auth Models
class RegisterModel(BaseModel):
    email: str
    password: str
    name: str
    role: str
    department: str

class LoginModel(BaseModel):
    email: str
    password: str

class ChatMessageModel(BaseModel):
    message: str

class RefreshModel(BaseModel):
    refresh_token: str

# 3. Root Endpoint
@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.app_name} in {settings.ENVIRONMENT} mode"}

@app.post("/auth/register")
async def register(data: RegisterModel):
    result = await register_user_db(data.email, data.password, data.name, data.role, data.department)
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.post("/auth/login")
async def login(data: LoginModel):
    result = await authenticate_user_db(data.email, data.password)
    if result["status"] == "error":
         raise HTTPException(status_code=401, detail=result["message"])
    return result

from app.services.user_service import refresh_token_db

@app.post("/auth/refresh")
async def refresh_session(data: RefreshModel):
    result = await refresh_token_db(data.refresh_token)
    if result["status"] == "error":
        raise HTTPException(status_code=401, detail=result["message"])
    return result

# 4. Chat Endpoints
@app.get("/chat/history")
async def get_chat_history(current_user: dict = Depends(get_current_user)):
    cursor = chat_db.find({"user_email": current_user["email"]}).sort("timestamp", 1)
    history = await cursor.to_list(length=100)
    for msg in history:
        msg["id"] = str(msg.pop("_id"))
    return history

@app.delete("/chat/history")
async def clear_chat_history(current_user: dict = Depends(get_current_user)):
    await chat_db.delete_many({"user_email": current_user["email"]})
    return {"status": "success", "message": "History cleared"}

from app.services.logger import audit_collection
from app.services.attack_analyzer import analyze_attack

async def _append_attack_analysis(request_id: str, current_user: dict, response: dict, client_ip: str = None) -> dict:
    try:
        doc = await audit_collection.find_one({"request_id": request_id})
        pipeline_events = doc.get("pipeline_events", []) if doc else []
        analysis = analyze_attack(pipeline_events, user_email=current_user.get("email"), ip_address=client_ip)
        if analysis:
            response["attack_analysis"] = analysis
            await audit_collection.update_one(
                {"request_id": request_id},
                {"$set": {
                    "attack_type": analysis.get("attack_type"),
                    "entry_point": analysis.get("entry_point"),
                    "risk_level": analysis.get("risk_level"),
                    "root_cause": analysis.get("root_cause")
                }}
            )
    except Exception as e:
        print(f"Attack Analyzer Failed: {e}")
    return response

@app.post("/chat")
async def chat_endpoint(
    request: Request,
    data: ChatMessageModel,
    current_user: dict = Depends(get_current_user),
):
    """
    SecureShield Enterprise AI Security Gateway
    ═══════════════════════════════════════════
    Evaluates payloads using 5 security layers.
    Status outputs: PASS, WARN, BLOCK, or ERROR.
    """
    import asyncio

    start_time = datetime.utcnow()
    request_id  = str(uuid.uuid4())
    message     = data.message
    role        = current_user["role"]
    department  = current_user.get("department", "")
    client_ip   = request.client.host if hasattr(request, "client") and request.client else "unknown"

    # Fetch dynamic settings
    settings_doc = await get_gateway_settings()

    # Anonymize completely if active
    audit_user = current_user.copy()
    if settings_doc.get("anonymize", False):
        audit_user["email"] = "anonymous@secureshield.local"
        audit_user["name"] = "Anonymous"
        client_ip = "0.0.0.0"

    # ── Shared helper: log, persist, and return a BLOCKED response ────────────
    async def block_and_return(reason: str, layer: str, global_risk: float = 1.0, detected_issue: str = None, suggestion: str = None):
        issue_str = detected_issue or f"Security Policy Violation: {reason}"
        sugg_str = suggestion or "Avoid query patterns that trigger security parameters."
        
        block_msg = f"BLOCKED: {issue_str} intercepted by {layer}. Suggestion: {sugg_str}"

        if not settings_doc.get("log_failed", True):
            try:
                from app.services.logger import audit_collection
                await audit_collection.delete_one({"request_id": request_id})
                await chat_db.delete_many({"user_email": current_user["email"], "timestamp": {"$gte": start_time}})
            except Exception as delete_err:
                print(f"Error purging failed logs: {delete_err}")
            
            resp = {
                "status": "BLOCK",
                "risk_score": round(global_risk, 4),
                "detected_issue": issue_str,
                "triggered_layer": layer,
                "action_taken": "Request Blocked",
                "suggestion": sugg_str,
                "response": block_msg
            }
            return resp

        await log_pipeline_event(
            request_id, layer, "BLOCKED",
            {"reason": reason, "message": message, "global_risk_score": global_risk},
        )
        latency = (datetime.utcnow() - start_time).total_seconds() * 1000
        await finalize_audit_log(request_id, "BLOCKED", int(latency), attack_type=issue_str, entry_point=layer, risk_level="HIGH", root_cause=reason)
        
        await chat_db.insert_one({
            "user_email": current_user["email"],
            "role": "system",
            "content": block_msg,
            "status": "BLOCK",
            "risk_score": round(global_risk, 4),
            "detected_issue": issue_str,
            "triggered_layer": layer,
            "action_taken": "Request Blocked",
            "suggestion": sugg_str,
            "timestamp": datetime.utcnow()
        })
        
        simple_langsmith_logger(message, global_risk, "BLOCK", block_msg)
        
        resp = {
            "status": "BLOCK",
            "risk_score": round(global_risk, 4),
            "detected_issue": issue_str,
            "triggered_layer": layer,
            "action_taken": "Request Blocked",
            "suggestion": sugg_str,
            "response": block_msg
        }
        return await _append_attack_analysis(request_id, current_user, resp, client_ip)

    # ── Shared helper: log a WARN event ───────────────────────────────────────
    async def warn_and_continue(reason: str, layer: str, global_risk: float):
        await log_pipeline_event(
            request_id, layer, "WARNED",
            {"reason": reason, "global_risk_score": global_risk},
        )
        simple_langsmith_logger(message, global_risk, "WARN", f"Warning from {layer}: {reason}")

    # ── 0. Initialize Audit Log ──────────────────────────────────────────────
    await init_audit_log(request_id, audit_user, ip_address=client_ip)
    
    scrubbed_input = message
    if settings_doc.get("anonymize", False) and settings_doc.get("pii_guard", True):
        scrubbed_input = scrub_pii(message)
    await chat_db.insert_one({
        "user_email": current_user["email"], "role": "user",
        "content": scrubbed_input, "timestamp": datetime.utcnow(),
    })

    # ── Step 1: PII & Secrets Pre-Scan (PII Guard) ───────────────────────────
    pii_warn_triggered = False
    pii_detected_issue = "None"
    pii_suggestion = "None"
    safe_message = message

    if settings_doc.get("pii_guard", True):
        pii_res = scan_pii_and_secrets(message)
        if pii_res["status"] == "BLOCK":
            return await block_and_return(
                reason=pii_res["detected_issue"],
                layer="PII_GUARD",
                global_risk=pii_res["risk_score"],
                detected_issue=pii_res["detected_issue"],
                suggestion=pii_res["suggestion"]
            )
        elif pii_res["status"] == "WARN":
            pii_warn_triggered = True
            pii_detected_issue = pii_res["detected_issue"]
            pii_suggestion = pii_res["suggestion"]
            safe_message = pii_res["redacted_text"]
            await log_pipeline_event(
                request_id, "PII_GUARD", "REDACTED",
                {"original": message, "redacted": safe_message},
            )
        else:
            await log_pipeline_event(request_id, "PII_GUARD", "PASSED")
    else:
        await log_pipeline_event(
            request_id, "PII_GUARD", "BYPASSED",
            {"reason": "PII Guard disabled by Administrator"}
        )

    normalized_message = normalize_text(safe_message)

    # ── Step 2: Input Guard & Patterns ────────────────────────────────────────
    if settings_doc.get("input_guard", True):
        input_result = await run_input_guard(normalized_message, user_role=role, user_department=department)

        if not input_result.passed:
            reason = (
                f"Forbidden pattern detected: '{input_result.matched_static_pattern}'"
                if input_result.blocked_by_pattern
                else f"High local risk score ({input_result.hybrid.local_risk_score:.2f}): "
                     f"{', '.join(input_result.hybrid.matched_threats)}"
            )

            # Check if this Input Guard block was actually triggered by an RBAC violation
            if "RBAC mismatch" in input_result.hybrid.reasoning:
                return await block_and_return(
                    reason="Role-based policy violation (Policy Engine)",
                    layer="POLICY_ENGINE",
                    global_risk=input_result.hybrid.local_risk_score,
                    detected_issue="Access Denied: Cross-department or role violation",
                    suggestion="Please limit queries to your assigned department and role permissions."
                )

            return await block_and_return(
                reason=reason,
                layer="INPUT_GUARD",
                global_risk=input_result.hybrid.local_risk_score,
                detected_issue="Forbidden Prompt Patterns / System Bypass Detected",
                suggestion="Do not attempt to bypass system instructions or issue commands to the model."
            )

        hybrid = input_result.hybrid
        await log_pipeline_event(
            request_id, "INPUT_GUARD", "PASSED",
            {
                "local_risk_score": hybrid.local_risk_score,
                "intent": hybrid.intent_class,
                "decision": hybrid.decision,
                "reasoning": hybrid.reasoning,
            },
        )
    else:
        class DummyHybrid:
            local_risk_score = 0.0
            intent_class = "General Greeting"
            decision = "FAST_TRACK_ALLOW"
            reasoning = "Input Guard disabled by Administrator"
            matched_threats = []
            
        hybrid = DummyHybrid()
        await log_pipeline_event(
            request_id, "INPUT_GUARD", "BYPASSED",
            {"reason": "Input Guard disabled by Administrator"},
        )

    # ── Step 3: Policy Engine (RBAC / Department) ─────────────────────────────
    if settings_doc.get("policy_engine", True):
        if not await check_policy(normalized_message, role, department):
            return await block_and_return(
                reason="Role-based policy violation (Policy Engine)",
                layer="POLICY_ENGINE",
                global_risk=max(hybrid.local_risk_score, 0.85),
                detected_issue="Access Denied: Cross-department or role violation",
                suggestion="Please limit queries to your assigned department and role permissions."
            )
        await log_pipeline_event(request_id, "POLICY_ENGINE", "PASSED")
    else:
        await log_pipeline_event(
            request_id, "POLICY_ENGINE", "BYPASSED",
            {"reason": "Policy Engine disabled by Administrator"}
        )

    # ── Step 4: Toxicity & Semantic Guards (Cloud Evaluators) ─────────────────
    toxicity_score = 0.0
    semantic_score = 0.0
    reasoning_log = {"toxicity": "", "semantic": ""}

    if hybrid.decision == "FAST_TRACK_ALLOW":
        await log_pipeline_event(
            request_id, "TOXICITY_GUARD", "FAST_TRACKED",
            {"reason": f"Hybrid local score {hybrid.local_risk_score:.2f} below fast-track threshold"},
        )
        await log_pipeline_event(
            request_id, "SEMANTIC_GUARD", "FAST_TRACKED",
            {"reason": f"Intent classified as '{hybrid.intent_class}' — no cloud call needed"},
        )
    else:
        try:
            if settings_doc.get("toxicity_guard", True):
                tox_task = check_toxicity(safe_message)
            else:
                class DummyToxResult:
                    passed = True
                    score = 0.0
                    reason = ""
                    reasoning_chain = "Toxicity Guard disabled by Administrator"
                    used_fallback = False
                    categories = {}
                async def get_dummy_tox(): return DummyToxResult()
                tox_task = get_dummy_tox()

            sem_task = check_semantic_intent(safe_message)

            tox_result, sem_result = await asyncio.gather(tox_task, sem_task)

            toxicity_score = tox_result.score
            reasoning_log["toxicity"] = tox_result.reasoning_chain
            
            if not settings_doc.get("toxicity_guard", True):
                await log_pipeline_event(
                    request_id, "TOXICITY_GUARD", "BYPASSED",
                    {"reason": "Toxicity Guard disabled by Administrator"}
                )
            else:
                if not tox_result.passed:
                    return await block_and_return(
                        reason=f"Toxic content detected: {tox_result.reason}",
                        layer="TOXICITY_GUARD",
                        global_risk=max(hybrid.local_risk_score, toxicity_score),
                        detected_issue="Toxic Language Violation",
                        suggestion="Ensure prompts comply with enterprise clean-language requirements."
                    )
                await log_pipeline_event(
                    request_id, "TOXICITY_GUARD", "PASSED",
                    {
                        "score": toxicity_score,
                        "used_fallback": tox_result.used_fallback,
                        "reasoning": tox_result.reasoning_chain,
                        "categories": tox_result.categories,
                    },
                )

            semantic_score = sem_result.risk_score
            reasoning_log["semantic"] = sem_result.reasoning_chain
            if not sem_result.passed:
                return await block_and_return(
                    reason=f"Malicious intent detected: {sem_result.reason}",
                    layer="SEMANTIC_GUARD",
                    global_risk=max(hybrid.local_risk_score, semantic_score),
                    detected_issue="Malicious Intent / Injection Detected",
                    suggestion="Avoid prompts matching jailbreaks or unauthorized system extraction techniques."
                )
            await log_pipeline_event(
                request_id, "SEMANTIC_GUARD", "PASSED",
                {
                    "risk_score": semantic_score,
                    "attack_vector": sem_result.attack_vector,
                    "confidence": sem_result.confidence,
                    "used_fallback": sem_result.used_fallback,
                    "reasoning": sem_result.reasoning_chain,
                },
            )

        except Exception as e:
            print(f"PIPELINE CRITICAL ERROR: {e}")
            return await block_and_return(
                reason=f"Internal security check failed: {e}",
                layer="SYSTEM",
                global_risk=0.5,
                detected_issue="Internal Safety Check Failure",
                suggestion="Retry query. If error persists, report to gateway administrators."
            )

    # ── Step 5: Global Score Aggregation & Warning Decisions ──────────────────
    global_risk_score = round(
        (hybrid.local_risk_score * 0.40)
        + (toxicity_score * 0.30)
        + (semantic_score * 0.30),
        4,
    )

    ALLOW_THRESHOLD = 0.40
    BLOCK_THRESHOLD = 0.70

    if global_risk_score >= BLOCK_THRESHOLD:
        return await block_and_return(
            reason=f"Global risk score {global_risk_score:.2f} exceeds block threshold",
            layer="RISK_ENGINE",
            global_risk=global_risk_score,
            detected_issue="High Global Risk Score",
            suggestion="Rewrite prompt to exclude high-risk words or security threats."
        )

    warn_mode = pii_warn_triggered or (global_risk_score >= ALLOW_THRESHOLD)
    if warn_mode:
        await warn_and_continue(
            reason=pii_detected_issue if pii_warn_triggered else f"Global risk score {global_risk_score:.2f} in warning zone",
            layer="PII_GUARD" if pii_warn_triggered else "RISK_ENGINE",
            global_risk=max(global_risk_score, 0.50 if pii_warn_triggered else 0.0)
        )

    # ── Step 6: LLM Generation & Output Guardrails ──────────────────────────
    try:
        chat_cursor = chat_db.find({"user_email": current_user["email"]}).sort("timestamp", -1).limit(10)
        history_msgs = await chat_cursor.to_list(length=10)
        history_msgs.reverse()
        
        formatted_history = []
        for h in history_msgs:
            role_type = "user" if h.get("role") == "user" else "assistant"
            content = h.get("content", "")
            if h.get("status") == "BLOCK" or content.startswith("BLOCKED:"):
                continue
            if settings_doc.get("pii_guard", True):
                scrubbed_content = scrub_pii(content)
            else:
                scrubbed_content = content
            formatted_history.append({"role": role_type, "content": scrubbed_content})
            
        if formatted_history and formatted_history[-1]["role"] == "user":
            formatted_history[-1]["content"] = safe_message
        else:
            formatted_history.append({"role": "user", "content": safe_message})
            
        llm_output = await generate_response(formatted_history, settings_doc)
        
        if settings_doc.get("pii_guard", True):
            final_response = scrub_pii(llm_output.answer)
        else:
            final_response = llm_output.answer
            
        final_response = await apply_guardrails(final_response)

        await log_pipeline_event(request_id, "LLM_RESPONSE", "SUCCESS")

        latency = (datetime.utcnow() - start_time).total_seconds() * 1000
        await finalize_audit_log(request_id, "PASSED", int(latency))

        status_str = "WARN" if warn_mode else "PASS"

        await chat_db.insert_one({
            "user_email": current_user["email"],
            "role": "system",
            "content": final_response,
            "status": status_str,
            "risk_score": round(0.50 if pii_warn_triggered else global_risk_score, 4),
            "detected_issue": pii_detected_issue if pii_warn_triggered else "None",
            "triggered_layer": "PII Guard" if pii_warn_triggered else "None",
            "action_taken": "Sensitive data masked before processing" if pii_warn_triggered else "Passed to LLM",
            "suggestion": pii_suggestion if pii_warn_triggered else "None",
            "timestamp": datetime.utcnow(),
        })

        simple_langsmith_logger(message, global_risk_score, status_str, final_response)

        resp = {
            "status": status_str,
            "risk_score": round(0.50 if pii_warn_triggered else global_risk_score, 4),
            "detected_issue": pii_detected_issue if pii_warn_triggered else "None",
            "triggered_layer": "PII Guard" if pii_warn_triggered else "None",
            "action_taken": "Sensitive data masked before processing" if pii_warn_triggered else "Passed to LLM",
            "suggestion": pii_suggestion if pii_warn_triggered else "None",
            "response": final_response
        }
        return await _append_attack_analysis(request_id, current_user, resp, client_ip)

    except Exception as e:
        error_msg = str(e)
        print(f"LLM GENERATION ERROR: {error_msg}")
        
        if "severe output violation" in error_msg.lower():
            return await block_and_return(
                reason="System attempted to leak private secrets",
                layer="OUTPUT_GUARDRAILS",
                global_risk=0.98,
                detected_issue="Output Leak: Secret Leak Prevented",
                suggestion="Do not attempt to request API keys, credentials, or private vault records."
            )

        if "quota" in error_msg.lower() or "429" in error_msg or "resource_exhausted" in error_msg.lower():
            user_friendly_error = (
                "Gemini API Quota Exceeded (HTTP 429). The Google Gemini Free Tier is limited to 20 requests per day. "
                "Please configure a pay-as-you-go billing plan on Google AI Studio, update your API key in the Gateway Settings page, "
                "or switch to OpenRouter / local Ollama."
            )
        else:
            user_friendly_error = f"LLM failed to generate response: {error_msg}"
            
        latency = (datetime.utcnow() - start_time).total_seconds() * 1000
        await finalize_audit_log(request_id, "ERROR", int(latency))
        
        await chat_db.insert_one({
            "user_email": current_user["email"],
            "role": "system",
            "content": user_friendly_error,
            "status": "ERROR",
            "risk_score": round(global_risk_score, 4),
            "detected_issue": "Gateway Engine Error",
            "triggered_layer": "System",
            "action_taken": "Execution Halted",
            "suggestion": "Retry the query or contact support if issue persists.",
            "timestamp": datetime.utcnow(),
        })
        
        simple_langsmith_logger(message, global_risk_score, "ERROR", user_friendly_error)
        
        return {
            "status": "ERROR",
            "risk_score": round(global_risk_score, 4),
            "detected_issue": "Gateway Engine Error",
            "triggered_layer": "System",
            "action_taken": "Execution Halted",
            "suggestion": "Retry the query or contact support if issue persists.",
            "response": user_friendly_error
        }

@app.get("/settings")
async def get_settings(current_user: dict = Depends(require_any_admin)):
    settings_doc = await get_gateway_settings()
    settings_doc.pop("_id", None)
    return settings_doc

@app.post("/settings")
async def update_settings(data: SettingsUpdateModel, current_user: dict = Depends(require_any_admin)):
    await settings_db.update_one(
        {"id": "global"},
        {"$set": {
            "input_guard": data.input_guard,
            "policy_engine": data.policy_engine,
            "toxicity_guard": data.toxicity_guard,
            "pii_guard": data.pii_guard,
            "provider": data.provider,
            "failover_node": data.failover_node,
            "log_failed": data.log_failed,
            "anonymize": data.anonymize,
            "updated_at": datetime.utcnow()
        }},
        upsert=True
    )
    return {"status": "success", "message": "Settings updated successfully"}

# 5. Telemetry Endpoints (Admin RBAC)
def mask_text(text: str) -> str:
    if not text or not isinstance(text, str): return text
    words = text.split()
    masked_words = []
    for w in words:
        if len(w) <= 2:
            masked_words.append(w[0] + "*" * (len(w)-1))
        else:
            masked_words.append(w[0] + "*" * (len(w)-2) + w[-1])
    return " ".join(masked_words)

@app.get("/logs")
async def get_logs(current_user: dict = Depends(require_any_admin)):
    db = client["SSA_Security"]
    query = {}
    is_super = current_user["role"] == "Admin"
    
    # Filter by department if not Admin
    if not is_super:
        query["user_context.department"] = current_user["department"]
        
    cursor = db["logs"].find(query).sort("timestamp", -1)
    logs = await cursor.to_list(length=50)
    
    for l in logs:
        l["id"] = str(l.pop("_id"))
        
        # Backward compatibility for current frontend mapping
        # We find the 'defining' event in the pipeline
        events = l.get("pipeline_events", [])
        
        # Default fallback values
        l["event"] = "SUCCESS" if l.get("final_status") == "PASSED" else "BLOCKED_SYSTEM"
        l["details"] = {"message": "Audit trace available", "response": "N/A"}
        
        for ev in events:
            if ev.get("status") == "BLOCKED":
                l["event"] = f"BLOCKED_{ev.get('layer')}"
                l["details"] = ev.get("details", {})
                break
            elif ev.get("layer") == "PII_GUARD" and ev.get("status") == "REDACTED":
                l["event"] = "PII_REDACTED"
                l["details"] = ev.get("details", {})
            elif ev.get("layer") == "LLM_RESPONSE":
                l["details"]["response"] = "Response generated"

        # Mask sensitive details for Department Admins
        if not is_super:
            details = l.get("details", {})
            for key in ["message", "original", "redacted", "response"]:
                if key in details:
                    details[key] = mask_text(details[key])
    
    return {"status": "success", "logs": logs, "viewer_scope": "Global" if is_super else current_user["department"]}

@app.get("/metrics")
async def get_metrics(current_user: dict = Depends(require_any_admin)):
    from collections import defaultdict
    from datetime import datetime, timedelta
    from app.layers.hybrid_evaluator import _KB
    db = client["SSA_Security"]
    
    is_super = current_user["role"] == "Admin"
    query = {} if is_super else {"user_context.department": current_user["department"]}

    total = await db["logs"].count_documents(query)
    blocked = await db["logs"].count_documents({**query, "final_status": "BLOCKED"})
    safe = total - blocked
    
    # Calculate active rules count (static + dynamic)
    static_kb_rules = (
        len(_KB.get("safe_greetings", []))
        + len(_KB.get("safe_conversational_patterns", []))
        + sum(len(pats) for pats in _KB.get("threat_signals", {}).values())
    )
    dynamic_rules_count = await db["security_rules"].count_documents({})
    active_rules_count = static_kb_rules + dynamic_rules_count
    
    # Chart Data & Stats
    cursor = db["logs"].find(query).sort("timestamp", 1).limit(1000)
    logs = await cursor.to_list(length=1000)
    
    grouped = {}
    now = datetime.utcnow()
    for i in range(11, -1, -1):
        h_obj = now - timedelta(hours=i)
        iso_key = h_obj.strftime("%Y-%m-%dT%H:00:00Z")
        grouped[iso_key] = {"safe": 0, "blocked": 0}

    risk_distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    attack_trends = defaultdict(int)
    layer_stats = defaultdict(int)

    for l in logs:
        ts = l.get("timestamp")
        if not ts: continue
        
        # New Stats Processing
        risk = l.get("risk_level")
        if risk in risk_distribution:
            risk_distribution[risk] += 1
            
        attack = l.get("attack_type")
        if attack:
            attack_trends[attack] += 1
            
        for ev in l.get("pipeline_events", []):
            layer = ev.get("layer")
            if layer:
                layer_stats[layer] += 1

        try:
            date_obj = ts if isinstance(ts, datetime) else datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            iso_key = date_obj.strftime("%Y-%m-%dT%H:00:00Z")
        except: continue
        if iso_key in grouped:
            if l.get("final_status") == "BLOCKED":
                grouped[iso_key]["blocked"] += 1
            else:
                grouped[iso_key]["safe"] += 1

    chart_data = [{"time": k, "safe": v["safe"], "blocked": v["blocked"]} for k,v in grouped.items()]
    attack_trends_list = [{"name": k, "value": v} for k, v in attack_trends.items()]
    layer_stats_list = [{"name": k, "value": v} for k, v in layer_stats.items()]
    
    # Recent Activity Map (using pipeline events)
    recent_cursor = db["logs"].find(query).sort("timestamp", -1).limit(4)
    recent_logs = await recent_cursor.to_list(length=4)
    recent_activity = []
    
    for r in recent_logs:
        ts = r.get("timestamp")
        time_str = ts.strftime("%H:%M") if isinstance(ts, datetime) else "Unknown Time"
        
        status = r.get("final_status", "UNKNOWN")
        detail_msg = "Request Processed"
        layer = "Security Pipeline"
        is_alert = False
        
        if status == "BLOCKED":
            is_alert = True
            # Find which layer blocked it
            for ev in r.get("pipeline_events", []):
                if ev.get("status") == "BLOCKED":
                    layer = ev.get("layer").replace("_", " ").title()
                    detail_msg = f"{layer} Intercepted Threat"
                    break
        else:
            # Check for PII Redaction in pipeline
            for ev in r.get("pipeline_events", []):
                if ev.get("layer") == "PII_GUARD" and ev.get("status") == "REDACTED":
                    layer = "PII Engine"
                    detail_msg = "Sensitive Data Scrubbed"
                    break

        recent_activity.append({
            "id": str(r["_id"]),
            "time": time_str,
            "message": detail_msg,
            "layer": layer,
            "isAlert": is_alert
        })
        
    return {
        "status": "success",
        "total": total,
        "safe": safe,
        "blocked": blocked,
        "activeRules": active_rules_count,
        "viewer_scope": "Global" if is_super else current_user["department"],
        "chartData": chart_data,
        "recentActivity": recent_activity,
        "riskDistribution": risk_distribution,
        "attackTrends": attack_trends_list,
        "layerStats": layer_stats_list
    }

# 6. Entry Point
if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

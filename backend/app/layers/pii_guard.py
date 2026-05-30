import json
import re
import os
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# Configure Presidio
configuration = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
}
provider = NlpEngineProvider(nlp_configuration=configuration)
analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
anonymizer = AnonymizerEngine()

# Load Corporate Vault
VAULT_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "corporate_vault.json")

def load_vault():
    try:
        with open(VAULT_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def scan_pii_and_secrets(text: str) -> dict:
    vault = load_vault()
    redacted_text = text
    detected_issue = None
    triggered_layer = "PII Guard"
    action_taken = "Passed"
    status = "PASS"
    risk_score = 0.0

    # 1. Patterns for BLOCK (Secrets, Credentials, Tokens)
    secret_patterns = {
        "OpenAI API Key": r"\bsk-[a-zA-Z0-9]{20,}\b",
        "Gemini API Key": r"\bAIzaSy[a-zA-Z0-9_-]{33}\b",
        "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
        "Generic Auth Token / Private Key": r"\b[A-Za-z0-9+/=]{32,}\b",
        "Explicit Password / Secret": r"(?i)\b(?:password|passwd|pwd|secret_key|api_key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-@#$!%*?&]{8,})['\"]?"
    }

    # 2. Patterns for WARN (PII, Identifiers, PAN, Emails, Phones)
    pii_patterns = {
        "PAN Number": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "Internal Identifier": r"\bEMP-\d{4,6}\b",
    }

    # --- Step A: Check for Secrets (BLOCK) ---
    for name, pattern in secret_patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            status = "BLOCK"
            risk_score = 0.95
            detected_issue = f"Secrets Leak Detected: {name}"
            action_taken = "Request Blocked"
            redacted_text = re.sub(pattern, "[REDACTED_SECRET]", redacted_text)

    # --- Step B: Check for PII / Identifiers (WARN) ---
    has_pii = False
    pii_detected_types = []

    for name, pattern in pii_patterns.items():
        matches = re.findall(pattern, redacted_text, re.IGNORECASE)
        if matches:
            has_pii = True
            pii_detected_types.append(name)
            redacted_text = re.sub(pattern, "[REDACTED_PII]", redacted_text, flags=re.IGNORECASE)

    # Check corporate vault items (employees, projects, server names)
    if vault:
        employees = vault.get("employees", [])
        for emp in employees:
            if re.search(rf"\b{re.escape(emp)}\b", redacted_text, re.IGNORECASE):
                has_pii = True
                pii_detected_types.append("Employee Name")
                redacted_text = re.sub(rf"\b{re.escape(emp)}\b", "[REDACTED_NAME]", redacted_text, flags=re.IGNORECASE)

        projects = vault.get("projects", [])
        for proj in projects:
            if re.search(rf"\b{re.escape(proj)}\b", redacted_text, re.IGNORECASE):
                has_pii = True
                pii_detected_types.append("Project Name")
                redacted_text = re.sub(rf"\b{re.escape(proj)}\b", "[REDACTED_PROJECT]", redacted_text, flags=re.IGNORECASE)

        servers = vault.get("infrastructure", {}).get("server_names", [])
        for srv in servers:
            if re.search(rf"\b{re.escape(srv)}\b", redacted_text, re.IGNORECASE):
                has_pii = True
                pii_detected_types.append("Server Hostname")
                redacted_text = re.sub(rf"\b{re.escape(srv)}\b", "[REDACTED_SERVER]", redacted_text, flags=re.IGNORECASE)

    # Presidio NLP analysis for general email/phone
    results = analyzer.analyze(
        text=redacted_text, 
        entities=["EMAIL_ADDRESS", "PHONE_NUMBER"], 
        language='en',
        score_threshold=0.3
    )

    if results:
        has_pii = True
        for r in results:
            pii_detected_types.append(r.entity_type.replace("_", " ").title())
        
        anonymized_result = anonymizer.anonymize(
            text=redacted_text,
            analyzer_results=results,
            operators={
                "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED_PII]"})
            }
        )
        redacted_text = anonymized_result.text

    # Set Warn status if PII found and not already blocked
    if has_pii and status != "BLOCK":
        status = "WARN"
        risk_score = 0.50
        unique_types = list(set(pii_detected_types))
        # Format nice detected issue
        detected_issue = f"PII Detected: {', '.join(unique_types)}"
        action_taken = "Sensitive data masked before processing"

    return {
        "status": status,
        "risk_score": risk_score,
        "detected_issue": detected_issue if detected_issue else "None",
        "triggered_layer": triggered_layer if detected_issue else "None",
        "action_taken": action_taken,
        "suggestion": "Avoid sharing credentials, passwords, or authentication keys." if status == "BLOCK" else ("Avoid sharing personal identification details." if status == "WARN" else "None"),
        "redacted_text": redacted_text
    }

def scrub_pii(text: str) -> str:
    res = scan_pii_and_secrets(text)
    return res["redacted_text"]
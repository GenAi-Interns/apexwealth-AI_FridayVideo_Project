from app.services.logger import client

async def _check_rbac(message: str, user_role: str, user_department: str = None) -> bool:
    """Helper function to evaluate RBAC rules based on user role and department."""
    msg = message.lower()
    
    # Admin -> global access (formerly Super Admin functionality)
    if user_role == "Admin":
        return True
        
    # Employee data only allowed for HR
    employee_data_keywords = ["employee data", "salary", "payroll", "performance review", "compensation", "wages", "worker info", "hr records", "paycheck", "bonus"]
    if any(kw in msg for kw in employee_data_keywords):
        if user_department != "HR":
            return False
            
    # Employee -> general queries only
    if user_role == "Employee":
        restricted_keywords = ["confidential", "financial report", "strategy", "admin panel", "secret", "proprietary", "internal docs", "earnings call"]
        if any(kw in msg for kw in restricted_keywords):
            return False
            
    return True

async def check_policy(message: str, user_role: str, user_department: str = None) -> bool:
    # 1. Fallback Intents
    malicious_intents = [
        "bypass security", "exploit", "drop database", "sudo rm",
        "show secret key", "reveal admin", "give me the password",
        "extract auth token", "list all users", "access restricted data"
    ]
    
    # 2. Dynamic Intents from MongoDB
    try:
        rules_cursor = client["SSA_Security"]["security_rules"].find({"type": "malicious_intent"})
        dynamic_rules = await rules_cursor.to_list(length=100)
        for rule in dynamic_rules:
            intent = rule.get("pattern")
            if intent and intent not in malicious_intents:
                malicious_intents.append(intent.lower())
    except Exception as e:
        print(f"⚠️ Could not load dynamic policies: {str(e)}")
    
    if any(intent in message.lower() for intent in malicious_intents):
        return False
        
    # 3. RBAC Check (New)
    try:
        if not await _check_rbac(message, user_role, user_department):
            return False
    except Exception as e:
        print(f"⚠️ RBAC check failed, falling back to existing behavior: {e}")
        # Fallback to existing behavior if RBAC logic fails
        pass
        
    return True

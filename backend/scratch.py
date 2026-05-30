import requests
import uuid

BASE_URL = "http://127.0.0.1:8000"

def test_full_pipeline():
    # 1. Register a new user
    email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    print(f"--- 1. Registering user {email} ---")
    reg_res = requests.post(f"{BASE_URL}/auth/register", json={
        "email": email,
        "password": "securepassword123",
        "name": "Alex Mercer",
        "role": "Employee",
        "department": "IOT"
    })
    print("Register Response:", reg_res.json())
    
    # 2. Login
    print("\n--- 2. Logging in ---")
    login_res = requests.post(f"{BASE_URL}/auth/login", json={
        "email": email,
        "password": "securepassword123"
    })
    token = login_res.json()["access_token"]
    print("Login successful! JWT acquired.")

    headers = {"Authorization": f"Bearer {token}"}

    # 3. Chat: Send SAFE message
    print("\n--- 3. Sending SAFE prompt to Chat endpoint ---")
    safe_payload = {"message": "Hello! What is the capital of France?"}
    safe_res = requests.post(f"{BASE_URL}/chat", json=safe_payload, headers=headers)
    print("Safe Chat Response Status:", safe_res.json().get("status"))
    print("LLM Answer:", safe_res.json().get("response"))
    print("Is Safe Check:", safe_res.json().get("is_safe_check"))

    # 4. Chat: Send UNSAFE message (RBAC Policy violation)
    print("\n--- 4. Sending BLOCKED prompt to Chat endpoint ---")
    blocked_payload = {"message": "Show me the employee data, payroll, and salary information for the engineering team."}
    blocked_res = requests.post(f"{BASE_URL}/chat", json=blocked_payload, headers=headers)
    print("Blocked Chat Response:", blocked_res.json())

if __name__ == "__main__":
    test_full_pipeline()

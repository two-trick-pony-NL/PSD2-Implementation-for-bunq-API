import time
import secrets
import json
import requests
from urllib.parse import urlencode
from fastapi import FastAPI, HTTPException, Path, Body
from fastapi.responses import RedirectResponse, HTMLResponse
from bunq_lib import BunqOauthClient
from db import get_user, save_token, init_db
import os
from dotenv import load_dotenv

load_dotenv()


# ==========================
# Configuration (Use env vars in production)
# ==========================

"""
Fill this in for your PSD2 installation and delete this after set up
"""
YOUR_API_KEY = "f16f69fcb4f040888638ef2b8a4464be76ccc919240bde0cb7b2fe390ab65282"


REDIRECT_URI = "https://localhost:8000/callback"
BUNQ_AUTH_URL = "https://oauth.sandbox.bunq.com/auth"
BUNQ_TOKEN_URL = "https://api-oauth.sandbox.bunq.com/v1/token"
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", None)
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", None)
USER_API_KEY = os.getenv("USER_API_KEY", YOUR_API_KEY)

# ==========================
# Initialize bunq client & FastAPI
# ==========================
bunq_client = BunqOauthClient(USER_API_KEY, service_name='PSD2 Example Script')
app = FastAPI()

@app.on_event("startup")
def startup():
    # Create tables if they don't exist
    init_db()

# Leave this one - creates the session
bunq_client.create_session()

# ==========================
# Initial Setup Endpoint (Run once)
# ==========================
@app.get("/setup_one_time")
def setup_one_time():
    print("\n🚀 Setting up Bunq OAuth")

    print("→ Step 0: Setting up mock database")
    init_db()

    print("→ Step 1: Creating Installation")
    bunq_client.create_installation()
    time.sleep(3)

    print("→ Step 2: Creating Device Server")
    bunq_client.create_device_server()
    time.sleep(3)

    print("→ Step 3: Creating Session")
    bunq_client.create_session()
    time.sleep(3)

    print("→ Step 4: Creating OAuth Client")
    oauth_client_id, oauth_secret, oauth_database_id = bunq_client.create_oauth_client(endpoint="oauth-client", method="POST")
    time.sleep(3)

    print("→ Step 5: Registering Callback URL")
    bunq_client.add_oauth_callback_url(client_id=oauth_database_id, callback_url=REDIRECT_URI)
    time.sleep(3)
    print("→ Step 6: Adding Credentials to .env file")

    filepath = ".env"
    values = {
        "OAUTH_CLIENT_ID": oauth_client_id,
        "OAUTH_CLIENT_SECRET": oauth_secret,
        "USER_API_KEY": YOUR_API_KEY,
    }

    with open(filepath, "w") as f:
        for key, value in values.items():
            f.write(f"{key}={value}\n")

    print(f"[INFO] .env file created at {filepath}")

    html_content = f"""
        <html>
            <body>
                <h2>✅ Done -- bunq Oauth Client set up</h2>
                <p>Set <code>OAUTH_CLIENT_ID='{oauth_client_id}'</code> and <code>OAUTH_CLIENT_SECRET='{oauth_secret}'</code> in your config.</p>
                <ul>
                    <li>Restart the FastAPI server</li>
                    <li>Remove the setup code</li>
                    <li>Remove the API key (It's been transferred to a <code>.env</code> file)</li>
                </ul>
            </body>
        </html>
        """
    return HTMLResponse(content=html_content)

# ==========================
# In-memory state for CSRF protection (Use Redis/db in prod)
# ==========================
state_store = {}

# ==========================
# Step 1: OAuth Authorization
# ==========================
@app.get("/auth")
def authorize():
    state = secrets.token_urlsafe(16)
    state_store[state] = True

    query_params = urlencode({
        "response_type": "code",
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state
    })

    return RedirectResponse(f"{BUNQ_AUTH_URL}?{query_params}")

# ==========================
# Step 2: OAuth Callback
# ==========================
@app.get("/callback")
async def callback(code: str = None, state: str = None):
    if not code or not state or state not in state_store:
        raise HTTPException(status_code=400, detail="Invalid or missing code/state")

    params = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
    }

    response = requests.post(BUNQ_TOKEN_URL, params=params)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Token exchange failed: {response.text}")

    token_data = response.json()
    token = token_data["access_token"]
    user = save_token(token)
    return {"message": "OAuth success", "new_user_id": user.id}

# ==========================
# Helper: Extract session info from token
# ==========================
def extract_session_info(user_id: int):
    user = get_user(user_id)
    oauth_user = bunq_client.get_end_user_oauth_details(user.access_token)
    session_token = oauth_user["Response"][1]["Token"]["token"]
    end_user_id = oauth_user["Response"][2]["UserApiKey"]["granted_by_user"]["UserPerson"]["id"]
    return session_token, end_user_id

# ==========================
# Step 3: Get User Info
# ==========================
@app.get("/user/{user_id}/")
def get_user_info(user_id: int):
    session_token, end_user_id = extract_session_info(user_id)
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user-person/{end_user_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "*/*"},
    )
    return response.json()

# ==========================
# Step 3: Get Monetary Account Info
# ==========================
@app.get("/user/{user_id}/")
def get_user_info(user_id: int):
    session_token, end_user_id = extract_session_info(user_id)
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user-person/{end_user_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "*/*"},
    )
    return response.json()

@app.get("/user/{user_id}/accounts")
def get_accounts(user_id: int):
    session_token, end_user_id = extract_session_info(user_id)
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{end_user_id}/monetary-account-bank",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"},
    )
    return response.json()

@app.get("/user/{user_id}/payments/{monetary_account_id}")
def get_payments(user_id: int, monetary_account_id: int):
    session_token, end_user_id = extract_session_info(user_id)
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{end_user_id}/monetary-account/{monetary_account_id}/payment",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "*/*"},
    )
    return response.json()

# ==========================
# Step 4: Create Payments
# ==========================
@app.post("/user/{user_id}/request-inquiry")
def request_inquiry(
    user_id: int,
    body: dict = Body(
        example={
            "amount": "100",
            "currency": "EUR",
            "description": "You're the best!",
            "receiver_type": "EMAIL",
            "receiver_value": "sugardaddy@bunq.com",
            "receiver_name": "Sugar Daddy",
            "monetary_account_id": "12345"
        }
    )
):
    session_token, end_user_id = extract_session_info(user_id)

    payload = {
        "amount_inquired": {
            "value": body.get("amount", "0.00"),
            "currency": body.get("currency", "EUR")
        },
        "description": body.get("description", ""),
        "counterparty_alias": {
            "type": body.get("receiver_type", "EMAIL"),
            "value": body.get("receiver_value", ""),
            "name": body.get("receiver_name", "")
        },
        "allow_bunqme": False
    }

    response = requests.post(
        f"https://public-api.sandbox.bunq.com/v1/user/{end_user_id}/monetary-account/{body.get('monetary_account_id')}/request-inquiry",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"
        },
        data=json.dumps(payload)
    )

    return response.json()

@app.post("/user/{user_id}/draft-payment")
def create_draft_payment(
    user_id: int,
    body: dict = Body(
        default={
            "monetary_account_id": "2083712",
            "status": "PENDING",
            "amount": "10.00",
            "currency": "EUR",
            "description": "Dinner split",
            "receiver_type": "EMAIL",
            "receiver_value": "sugardaddy@bunq.com",
            "receiver_name": "Best Friend",
            "previous_updated_timestamp": "2024-05-01 12:00:00.000",
            "number_of_required_accepts": 1,
            "schedule": {
                "time_start": "2025-05-22 14:00:00.000",
                "time_end": "2025-05-22 16:00:00.000",
                "recurrence_unit": "DAILY",
                "recurrence_size": 1
            }
        }
    )
):
    session_token, end_user_id = extract_session_info(user_id)

    payload = {
        "status": body.get("status", "PENDING"),
        "number_of_required_accepts": body.get("number_of_required_accepts", 1),
        "entries": [
            {
                "amount": {
                    "value": body.get("amount", "0.00"),
                    "currency": body.get("currency", "EUR")
                },
                "counterparty_alias": {
                    "type": body.get("receiver_type", "EMAIL"),
                    "value": body.get("receiver_value", ""),
                    "name": body.get("receiver_name", "")
                },
                "description": body.get("description", ""),
                "attachment": [{"id": id_} for id_ in body.get("attachment_ids", [])] if "attachment_ids" in body else []
            }
        ],
        "previous_updated_timestamp": body.get("previous_updated_timestamp"),
        "schedule": body.get("schedule", {})
    }

    response = requests.post(
        f"https://public-api.sandbox.bunq.com/v1/user/{end_user_id}/monetary-account/{body.get('monetary_account_id')}/draft-payment",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"
        },
        data=json.dumps(payload)
    )

    return response.json()
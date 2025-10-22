import time
import secrets
import json
import requests
from urllib.parse import urlencode
from fastapi import FastAPI, HTTPException, Path, Body, Header
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import RedirectResponse, HTMLResponse, StreamingResponse
from bunq_lib import BunqOauthClient
from db import get_user, save_token, init_db
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import logging
from utils import log_request

load_dotenv()


# Patch the Session.request method globally
requests.Session.request = log_request


# ==========================
# Configuration (Use env vars in production)
# ==========================

"""
Fill this in for your PSD2 installation and delete this after set up
"""
YOUR_API_KEY = "a8f259028e06d00e4359e7603392667f0b7a6eab8d5f605dd8b0de56f2e0e8f5"


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
bunq_client.create_session()

app = FastAPI(
    title="bunq API Example",
    description="""
Welcome to the **bunq API Example** This implementation is aimed at demonstrating how to use bunq's OAuth2 flow and interact with their API using FastAPI. 
Refer to the readme.md to see how to get the setup working. Each of these endpoints allows you to interact with bunq's API in the role of PSD2 user on behalf of a bunq user after completing the OAuth2 authorization process.

refer to https://doc.bunq.com for all API documentation

""",
    version="1.0.0"
)


@app.on_event("startup")
def startup():
    # Create tables if they don't exist
    init_db()


# ==========================
# Initial Setup Endpoint (Run once)
# ==========================

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def read_root():
    return RedirectResponse(url="/docs")


@app.get("/setup_one_time", response_class=HTMLResponse, include_in_schema=False)
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
@app.get("/auth", tags=["oauth"])
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
@app.get("/callback", tags=["oauth"])
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
    #print(oauth_user)
    session_token = oauth_user["Response"][1]["Token"]["token"]
    end_user_id = oauth_user["Response"][2]["UserApiKey"]["granted_by_user"]["UserPerson"]["id"]
    user_api_key = oauth_user["Response"][2]["UserApiKey"]["id"]
    return session_token, end_user_id, user_api_key

# ==========================
# Step 3: Get User Info
# ==========================
@app.get("/user/{user_id}/", tags=["Userprofile"])
def get_user_info(user_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "*/*"},
    )
    return response.json()

# ==========================
# Step 3: Get Monetary Account Info
# ==========================
@app.get("/user/{user_id}/accounts", tags=["Monetary Accounts"])
def get_accounts(user_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}/monetary-account",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"},
    )
    return response.json()

@app.get("/user/{user_id}/payments/{monetary_account_id}", tags=["Payments"])
def get_payments(user_id: int, monetary_account_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}/payment",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "*/*"},
    )
    return response.json()

@app.get("/user/{user_id}/monetary-account/{monetary_account_id}/draft-payment/{payment_id}/", tags=["Payments"])
def get_draft_payment(user_id: int, monetary_account_id: int, payment_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}/draft-payment/{payment_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "*/*"},
    )
    return response.json()

@app.get("/user/{user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/", tags=["Payments"])
def get_payment(user_id: int, monetary_account_id: int, payment_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}/payment/{payment_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "*/*"},
    )
    return response.json()

# ==========================
# Step 4: Create Payments
# ==========================



@app.post("/user/{user_id}/request-inquiry", tags=["Requests"])
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
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)

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
        f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}/monetary-account/{body.get('monetary_account_id')}/request-inquiry",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"
        },
        data=json.dumps(payload)
    )

    return response.json()

# -----------------------------
# Draft payment
# -----------------------------
@app.post(
    "/user/{user_id}/draft-payment",
    tags=["Payments"],
    summary="Create a draft payment",
)
def create_draft_payment(
    user_id: int,
    body: dict = Body(
        ...,
        example={
            "monetary_account_id": "2083712",
            "status": "PENDING",
            "amount": "10.00",
            "currency": "EUR",
            "description": "Dinner split",
            "receiver_type": "EMAIL",
            "receiver_value": "sugardaddy@bunq.com",
            "receiver_name": "Best Friend",
            "previous_updated_timestamp": "2024-05-01 12:00:00.000",
            "number_of_required_accepts": 1
        }
    )
):
    session_token, _, user_api_key_id = extract_session_info(user_id)
    now = datetime.utcnow() + timedelta(hours=1)
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
    "schedule": {
        "time_start": now.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        "time_end": (now + timedelta(minutes=5)).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        "recurrence_unit": "DAILY",
        "recurrence_size": 1
        }
    }

    response = requests.post(
        f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}/monetary-account/{body.get('monetary_account_id')}/draft-payment",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"
        },
        data=json.dumps(payload)
    )

    return response.json()


# -----------------------------
# Draft payment batch
# -----------------------------
@app.post(
    "/user/{user_id}/draft-payment-batch",
    tags=["Payments"],
    summary="Create a draft payment batch",
)
def create_draft_payment_batch(
    user_id: int,
    body: list[dict] = Body(
        ...,
        example=[
            {
                "monetary_account_id": "2083712",
                "status": "PENDING",
                "amount": "10.00",
                "currency": "EUR",
                "description": "Payment 1",
                "receiver_type": "EMAIL",
                "receiver_value": "sugardaddy@bunq.com",
                "receiver_name": "Best Friend",
                "previous_updated_timestamp": "2024-05-01 12:00:00.000",
                "number_of_required_accepts": 1
            },
            {
                "monetary_account_id": "2083712",
                "status": "PENDING",
                "amount": "15.50",
                "currency": "EUR",
                "description": "Payment 2",
                "receiver_type": "EMAIL",
                "receiver_value": "sugardaddy@bunq.com",
                "receiver_name": "Alice",
                "previous_updated_timestamp": "2024-05-01 12:00:00.000",
                "number_of_required_accepts": 1
            },
            {
                "monetary_account_id": "2083712",
                "status": "PENDING",
                "amount": "15.50",
                "currency": "EUR",
                "description": "Payment 3",
                "receiver_type": "IBAN",
                "receiver_value": "NL14RABO0169202917",
                "receiver_name": "Peter",
                "previous_updated_timestamp": "2024-05-01 12:00:00.000",
                "number_of_required_accepts": 1
            }
        ]
    )
):
    session_token, _, user_api_key_id = extract_session_info(user_id)
    responses = []
    now = datetime.utcnow() + timedelta(hours=1)

    for item in body:
        payload = {
            "status": item.get("status", "PENDING"),
            "number_of_required_accepts": item.get("number_of_required_accepts", 1),
            "entries": [
                {
                    "amount": {
                        "value": item.get("amount", "0.00"),
                        "currency": item.get("currency", "EUR")
                    },
                    "counterparty_alias": {
                        "type": item.get("receiver_type", "EMAIL"),
                        "value": item.get("receiver_value", ""),
                        "name": item.get("receiver_name", "")
                    },
                    "description": item.get("description", ""),
                    "attachment": [{"id": id_} for id_ in item.get("attachment_ids", [])] if "attachment_ids" in item else []
                }
            ],
            "previous_updated_timestamp": item.get("previous_updated_timestamp"),
            "schedule": {
                "time_start": now.strftime("%Y-%m-%d %H:%M:%S.000"),
                "time_end": (now + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S.000"),
                "recurrence_unit": "DAILY",
                "recurrence_size": 1
            }
        }

        response = requests.post(
            f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}/monetary-account/{item.get('monetary_account_id')}/draft-payment",
            headers={
                "User-Agent": "text",
                "X-Bunq-Client-Authentication": session_token,
                "Content-Type": "application/json"
            },
            data=json.dumps(payload)
        )
        responses.append(response.json())

    return responses

@app.post("/psd2/payment-service-provider-issuer-transaction", tags=["PSD2 User"])
def create_payment_service_provider_issuer_transaction(
    body: dict = Body(
        default={
            "counterparty_alias": {
                "type": "IBAN",
                "value": "NL14RABO0169202917",
                "name": "Test Merchant"
            },
            "amount": {
                "value": "10.00",
                "currency": "EUR"
            },
            "description": "Payment description",
            "url_redirect": "https://yourapp.com/redirect",
            "time_expiry": (datetime.utcnow() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "status": "PENDING"
        }
    ),
):

    payload = {
        "counterparty_alias": body.get("counterparty_alias"),
        "amount": body.get("amount"),
        "description": body.get("description"),
        "url_redirect": body.get("url_redirect"),
        "time_expiry": body.get("time_expiry"),
        "status": body.get("status")
    }

    headers = {
        "Cache-Control": "no-cache",
        "X-Bunq-Client-Authentication": str(bunq_client.session_token), #Session token from PSD2 user
        "Content-Type": "application/json",
        "Accept": "*/*"
    }

    response = requests.post(
        f"https://public-api.sandbox.bunq.com/v1/user/{bunq_client.user_id}/payment-service-provider-issuer-transaction", #PSD2 user ID 
        headers=headers,
        data=json.dumps(payload)
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()


# ==========================
# Step 5: PSD2 Payment issuer Payments
# ==========================

@app.get("/psd2/payment-service-provider-issuer-transaction/{transaction_id}", tags=["PSD2 User"])
def get_payment_service_provider_issuer_transaction(transaction_id: int):

    headers = {
        "Cache-Control": "no-cache",
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Content-Type": "application/json",
        "Accept": "*/*"
    }

    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{bunq_client.user_id}/payment-service-provider-issuer-transaction/{transaction_id}",
        headers=headers
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()


@app.get("/psd2/payment-service-provider-issuer-transaction-public/{public_id}", tags=["PSD2 User"])
def get_payment_service_provider_issuer_transaction(public_id: str):

    headers = {
        "Cache-Control": "no-cache",
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Content-Type": "application/json",
        "Accept": "*/*"
    }

    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{bunq_client.user_id}/payment-service-provider-issuer-transaction-public/{public_id}",
        headers=headers
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()


# ==========================
# Step 6: Update Whitelist  IP addresses
# ==========================

@app.get("/credential-password-ip", tags=["IP Whitelist"])
def list_credential_password_ips():
    headers = {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Accept": "application/json",
    }

    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{bunq_client.user_id}/credential-password-ip",
        headers=headers
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()

@app.get("/credential-password-ip/{ip_id}", tags=["IP Whitelist"])
def get_credential_password_ip(ip_id: int):
    headers = {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Accept": "application/json",
    }

    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{bunq_client.user_id}/credential-password-ip/{ip_id}",
        headers=headers
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()


import uuid

@app.get("/credential-password-ip/{credential_password_ip_id}", tags=["IP Whitelist"])
def get_credential(credential_password_ip_id: int):
    headers = {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Accept": "application/json",
    }
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{bunq_client.user_id}/credential-password-ip/{credential_password_ip_id}",
        headers=headers
    )
    return response.json()

@app.get("/credential-password-ip/{credential_password_ip_id}/ip", tags=["IP Whitelist"])
def list_ips_for_credential(credential_password_ip_id: int):
    headers = {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Accept": "application/json",
    }
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{bunq_client.user_id}/credential-password-ip/{credential_password_ip_id}/ip",
        headers=headers
    )
    return response.json()

@app.get("/credential-password-ip/{credential_password_ip_id}/ip/{item_id}", tags=["IP Whitelist"])
def get_ip_for_credential(credential_password_ip_id: int, item_id: int):
    headers = {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Accept": "application/json",
    }
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{bunq_client.user_id}/credential-password-ip/{credential_password_ip_id}/ip/{item_id}",
        headers=headers
    )
    return response.json()



@app.post("/credential-password-ip/{credential_password_ip_id}/ip", tags=["IP Whitelist"])
def add_ip_for_credential(credential_password_ip_id: int, body: dict = Body(
    default={
        "ip": "*",
        "status": "ACTIVE"
    }
)):
    """
    Add a new IP to the list of allowed IPs for a credential-password-ip object.

    Example default body:
    {
        "ip": "*",
        "status": "ACTIVE"
    }
    """
    payload = {
        "ip": body.get("ip", "*"),
        "status": body.get("status", "ACTIVE")
    }

    headers = {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "X-Bunq-Language": "en_US",
        "X-Bunq-Region": "nl_NL",
        "X-Bunq-Geolocation": "0 0 0 0 NL",
        "X-Bunq-Client-Request-Id": str(uuid.uuid4()),
        "User-Agent": "bunq-api-client/1.0",
        "Cache-Control": "no-cache",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    url = (
        f"https://public-api.sandbox.bunq.com/v1/user/{bunq_client.user_id}/"
        f"credential-password-ip/{credential_password_ip_id}/ip"
    )

    response = requests.post(
        url,
        headers=headers,
        data=json.dumps(payload)
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()



@app.put("/credential-password-ip/{credential_password_ip_id}/ip/{item_id}", tags=["IP Whitelist"])
def update_ip_status_for_credential(credential_password_ip_id: int, item_id: int, body: dict = Body(
    default={
        "status": "INACTIVE"
    }
)):
    """
    Update the status of an existing IP entry for a credential-password-ip.
    Only "status" is allowed here.

    Example default body:
    {
        "status": "INACTIVE"
    }
    """
    payload = {
        "status": body.get("status", "INACTIVE"),
    }

    headers = {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "X-Bunq-Language": "en_US",
        "X-Bunq-Region": "nl_NL",
        "X-Bunq-Geolocation": "0 0 0 0 NL",
        "X-Bunq-Client-Request-Id": str(uuid.uuid4()),
        "User-Agent": "bunq-api-client/1.0",
        "Cache-Control": "no-cache",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    url = (
        f"https://public-api.sandbox.bunq.com/v1/user/{bunq_client.user_id}/"
        f"credential-password-ip/{credential_password_ip_id}/ip/{item_id}"
    )

    response = requests.put(
        url,
        headers=headers,
        data=json.dumps(payload)
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()

# ---- GET notification filters ----
@app.get("/user/{user_id}/notification-filter-url", tags=["Notification Filters"])
def get_notification_filters(user_id: int):
    """
    Retrieve all URL notification filters for a user.
    """
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    headers = {
        "X-Bunq-Client-Authentication": session_token,
        "X-Bunq-Language": "en_US",
        "X-Bunq-Region": "nl_NL",
        "X-Bunq-Geolocation": "0 0 0 0 NL",
        "X-Bunq-Client-Request-Id": str(uuid.uuid4()),
        "User-Agent": "bunq-api-client/1.0",
        "Cache-Control": "no-cache",
        "Accept": "application/json",
    }

    url = f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}/notification-filter-url"

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    return response.json()


# ---- POST / set notification filters ----
@app.post("/user/{user_id}/notification-filter-url", tags=["Notification Filters"])
def set_notification_filter(
    user_id: int,
    body: dict = Body(
        default={
            "notification_filters": [
                {"category": "BILLING", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "CARD_TRANSACTION_SUCCESSFUL", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "CARD_TRANSACTION_FAILED", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "CHAT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "DRAFT_PAYMENT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "IDEAL", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "SOFORT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "MUTATION", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "OAUTH", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "PAYMENT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "REQUEST", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "SCHEDULE_RESULT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "SCHEDULE_STATUS", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "SHARE", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "TAB_RESULT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "BUNQME_TAB", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "SUPPORT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"}
            ]
        }
    )
):
    """
    Manage the URL notification filters for a user.

    Example default body:
    {
        "notification_filters": [
            {
                "category": "CARD_TRANSACTIONSUCCESSFUL",
                "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"
            }
        ]
    }
    """
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    headers = {
        "X-Bunq-Client-Authentication": session_token,
        "X-Bunq-Language": "en_US",
        "X-Bunq-Region": "nl_NL",
        "X-Bunq-Geolocation": "0 0 0 0 NL",
        "X-Bunq-Client-Request-Id": str(uuid.uuid4()),
        "User-Agent": "bunq-api-client/1.0",
        "Cache-Control": "no-cache",
        "Accept": "application/json",
    }

    url = f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}/notification-filter-url"

    response = requests.post(url, headers=headers, data=json.dumps(body))
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()

# ---- GET notification filters ----
@app.get("/user/{user_id}/notification-filter-failure", tags=["Notification Filters"])
def get_notification_filters(user_id: int):
    """
    Retrieve all URL notification failures for a user.
    """
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    headers = {
        "X-Bunq-Client-Authentication": session_token,
        "X-Bunq-Language": "en_US",
        "X-Bunq-Region": "nl_NL",
        "X-Bunq-Geolocation": "0 0 0 0 NL",
        "X-Bunq-Client-Request-Id": str(uuid.uuid4()),
        "User-Agent": "bunq-api-client/1.0",
        "Cache-Control": "no-cache",
        "Accept": "application/json",
    }

    url = f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}/notification-filter-failure"

    response = requests.get(url, headers=headers)
    print(response.headers)

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    return response.json()


@app.put("/user/{user_id}/notification-filter-url", tags=["Notification Filters"])
def set_notification_filter(
    user_id: int,
    body: dict = Body(
        default={
            "notification_filters": [
                {"category": "BILLING", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "CARD_TRANSACTION_SUCCESSFUL", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "CARD_TRANSACTION_FAILED", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "CHAT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "DRAFT_PAYMENT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "IDEAL", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "SOFORT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "MUTATION", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "OAUTH", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "PAYMENT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "REQUEST", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "SCHEDULE_RESULT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "SCHEDULE_STATUS", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "SHARE", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "TAB_RESULT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "BUNQME_TAB", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"},
                {"category": "SUPPORT", "notification_target": "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"}
            ]
        }
    )
):
    """
    Manage the URL notification filters for a user.

    Example default body:
    {
        "notification_filters": []
    }
    """
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    headers = {
        "X-Bunq-Client-Authentication": session_token,
        "X-Bunq-Language": "en_US",
        "X-Bunq-Region": "nl_NL",
        "X-Bunq-Geolocation": "0 0 0 0 NL",
        "X-Bunq-Client-Request-Id": str(uuid.uuid4()),
        "User-Agent": "bunq-api-client/1.0",
        "Cache-Control": "no-cache",
        "Accept": "application/json",
    }

    url = f"https://public-api.sandbox.bunq.com/v1/user/{user_api_key_id}/notification-filter-url"

    response = requests.put(url, headers=headers, data=json.dumps(body))
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()


@app.get("/user/{user_id}/monetary-account/{account_id}/bunqme-tab/", tags=["bunqme"])
def get_bunqme_tabs(user_id: int, account_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user/{end_user_id}/monetary-account/{account_id}/bunqme-tab",
        headers={
            "User-Agent": "bunq-python/1.0",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "application/json",
        },
    )
    return response.json()


@app.post("/user/{user_id}/monetary-account/{account_id}/bunqme-tab/", tags=["bunqme"])
def create_bunqme_tab(
    user_id: int,
    account_id: int,
    tab_entry: dict = Body(..., example={
        "bunqme_tab_entry": {
            "amount_inquired": {"value": "10.00", "currency": "EUR"},
            "description": "Lunch",
            "redirect_url": "https://example.com/return"
        },
        "status": "ACTIVE",
        "event_id": 1
    })
):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.post(
        f"https://public-api.sandbox.bunq.com/v1/user/{end_user_id}/monetary-account/{account_id}/bunqme-tab",
        json=tab_entry,
        headers={
            "User-Agent": "bunq-python/1.0",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    return response.json()




# -------------------------
# Attachments
# -------------------------
# ==========================
# New Endpoint: Upload Attachment
# ==========================
@app.post("/user/{user_id}/monetary-account/{monetary_account_id}/attachment", tags=["Attachments"])
async def create_monetary_account_attachment(
    user_id: int, 
    monetary_account_id: int,
    file: UploadFile = File(..., description="The file to upload as an attachment."),
    description: str = Form(..., description="A brief description of the file.")
):
    """
    Creates a new attachment and immediately links it to a specific monetary account.

    This uses the POST /user/{userID}/monetary-account/{monetary-accountID}/attachment endpoint.
        User: 20
    MA: 	3411122
    payment: 28393087
    Attachment ID: 8cd97c1d-d530-42ef-8854-c69ae5902a2f

    
    """
    try:
        session_token, end_user_id, api_key_user_id = extract_session_info(user_id)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found or session invalid: {e}")

    file_content = await file.read()
    if not file_content:
        raise HTTPException(status_code=400, detail="The uploaded file cannot be empty.")

    headers = {
        "User-Agent": "FastAPI Bunq App",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": file.content_type,
        "X-Bunq-Attachment-Description": description,
    }

    # 1. CRITICAL FIX: The URL is now an f-string to correctly insert the IDs.
    url = f"https://public-api.sandbox.bunq.com/v1/user/{api_key_user_id}/monetary-account/{monetary_account_id}/attachment"

    # Make the request to the bunq API
    response = requests.post(
        url,
        headers=headers,
        data=file_content
    )
    
    # 2. IMPROVEMENT: Added error handling.
    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Failed to create attachment on monetary account: {response.text}"
        )

    # Return the successful response from bunq, which contains the new attachment's ID
    return response.json()

    
    
@app.post("/user/{user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-attachment", tags=["Attachments"])
def add_attachment_to_payment(
    user_id: int, 
    monetary_account_id: int, 
    payment_id: int,
    attachment_id: int = Form(..., description="The ID of the attachment to link."),
    description: str = Form(None, description="An optional description for the note-attachment.")
):
    """
    Adds an existing attachment to a payment as a 'note-attachment'.
    
    The request body must contain the attachment_id of the attachment 
    that was created via the /attachment-public endpoint.
    
    User: 20
    MA: 	3320038 
    payment: 28472876
    Attachment ID: 6436861

    
    """
    
    session_token, end_user_id, api_key_user_id = extract_session_info(user_id)


    headers = {
        "User-Agent": "FastAPI Bunq App",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": "application/json"
    }
    
    
    request_body = {
        "attachment_id": attachment_id,
    }
    
    # Add description only if provided
    if description:
        request_body["description"] = description

    url = f"https://public-api.sandbox.bunq.com/v1/user/{end_user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-attachment"

    response = requests.post(
        url,
        headers=headers,
        json=request_body # Use the 'json' parameter for automatic JSON encoding
    )
    return response.json()

@app.post("/user/{user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-text", tags=["Attachments"])
def add_attachment_to_payment(
    user_id: int, 
    monetary_account_id: int, 
    payment_id: int,
    text: str = Form(None, description="A text for with this payment.")
):
    """
    Adds an existing attachment to a payment as a 'note-text'.
    
    
    User: 20
    MA: 	3320038 
    payment: 28472876

    
    """
    
    session_token, end_user_id, api_key_user_id = extract_session_info(user_id)


    headers = {
        "User-Agent": "FastAPI Bunq App",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": "application/json"
    }
    
    
    request_body = {
        "content": text,
    }
    

    url = f"https://public-api.sandbox.bunq.com/v1/user/{end_user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-text"

    response = requests.post(
        url,
        headers=headers,
        json=request_body # Use the 'json' parameter for automatic JSON encoding
    )
    return response.json()
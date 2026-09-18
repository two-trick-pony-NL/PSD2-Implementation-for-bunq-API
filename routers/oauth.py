import secrets
import requests
from urllib.parse import urlencode
from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
from db import save_token
from dependencies import BUNQ_AUTH_URL, BUNQ_TOKEN_URL, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, REDIRECT_URI, bunq_client

router = APIRouter()

# In-memory state for CSRF protection (use Redis/db in prod)
state_store = {}


@router.get("/auth", tags=["oauth"])
def authorize():
    state = secrets.token_urlsafe(16)
    state_store[state] = True

    query_params = urlencode({
        "response_type": "code",
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "scope": "read_monetary_accounts make_payments request_payments bunqme"
    })

    return RedirectResponse(f"{BUNQ_AUTH_URL}?{query_params}")


@router.get("/callback", tags=["oauth"])
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


@router.get("/oauth-clients", tags=["oauth"])
def list_oauth_clients():
    try:
        return bunq_client.list_oauth_clients()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/oauth-client/{client_db_id}/callback-url", tags=["oauth"])
def list_callback_urls(client_db_id: str):
    try:
        return bunq_client.list_oauth_callback_urls(client_id=client_db_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/oauth-client/{client_db_id}/callback-url", tags=["oauth"])
def add_callback_url(client_db_id: str, callback_url: str):
    try:
        result = bunq_client.add_oauth_callback_url(client_id=client_db_id, callback_url=callback_url)
        return {"message": "Callback URL added", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

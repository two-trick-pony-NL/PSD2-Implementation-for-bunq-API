import uuid
import requests
from fastapi import APIRouter
from dependencies import BASE_URL, extract_session_info

router = APIRouter()


def _headers(session_token: str) -> dict:
    return {
        "User-Agent": "FastAPI Bunq App",
        "X-Bunq-Language": "en_US",
        "X-Bunq-Region": "nl_NL",
        "X-Bunq-Client-Request-Id": str(uuid.uuid4()),
        "X-Bunq-Geolocation": "0 0 0 0 NL",
        "X-Bunq-Client-Authentication": session_token,
        "Cache-Control": "no-cache",
        "Accept": "application/json",
    }


@router.get("/user/{user_id}/additional-transaction-information-category", tags=["Additional Transaction Info"])
def get_additional_transaction_information_category(user_id: int):
    """Get the available additional transaction information categories for a user."""
    session_token, end_user_id, api_key_user_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{end_user_id}/additional-transaction-information-category"
    response = requests.get(url, headers=_headers(session_token))
    try:
        return response.json()
    except Exception:
        return {"error": "Failed to parse JSON", "text": response.text}


@router.get("/user/{user_id}/event", tags=["Events"])
def get_events(user_id: int):
    """Get the list of all events for a user."""
    session_token, end_user_id, api_key_user_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{api_key_user_id}/event"
    response = requests.get(url, headers=_headers(session_token))
    try:
        return response.json()
    except Exception:
        return {"error": "Failed to parse JSON", "text": response.text}


@router.get("/user/{user_id}/event/{item_id}", tags=["Events"])
def get_event_by_id(user_id: int, item_id: int):
    """Get a specific event by its ID for a user."""
    session_token, end_user_id, api_key_user_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{api_key_user_id}/event/{item_id}"
    response = requests.get(url, headers=_headers(session_token))
    try:
        return response.json()
    except Exception:
        return {"error": "Failed to parse JSON", "text": response.text}


@router.get("/user/{user_id}/mastercard_action/", tags=["Mastercard Action"])
def list_mastercard_action(user_id: int, monetary_account_id):
    session_token, end_user_id, api_key_user_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{api_key_user_id}/monetary-account/{monetary_account_id}/mastercard-action/"
    response = requests.get(url, headers=_headers(session_token))
    try:
        return response.json()
    except Exception:
        return {"error": "Failed to parse JSON", "text": response.text}


@router.get("/user/{user_id}/mastercard_action/{item_id}", tags=["Mastercard Action"])
def get_mastercard_action(user_id: int, monetary_account_id, item_id: int):
    session_token, end_user_id, api_key_user_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{api_key_user_id}/monetary-account/{monetary_account_id}/mastercard-action/{item_id}"
    response = requests.get(url, headers=_headers(session_token))
    try:
        return response.json()
    except Exception:
        return {"error": "Failed to parse JSON", "text": response.text}

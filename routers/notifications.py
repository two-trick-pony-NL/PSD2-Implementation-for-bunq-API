import json
import uuid
import requests
from fastapi import APIRouter, Body, HTTPException
from dependencies import BASE_URL, extract_session_info

router = APIRouter()

_WEBHOOK_EXAMPLE = "https://webhook.site/994966bb-7a4c-4be3-836a-da65231b907d"

_DEFAULT_FILTERS = [
    {"category": "BILLING", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "CARD_TRANSACTION_SUCCESSFUL", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "CARD_TRANSACTION_FAILED", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "CHAT", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "DRAFT_PAYMENT", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "IDEAL", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "SOFORT", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "MUTATION", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "OAUTH", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "PAYMENT", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "REQUEST", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "SCHEDULE_RESULT", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "SCHEDULE_STATUS", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "SHARE", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "TAB_RESULT", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "BUNQME_TAB", "notification_target": _WEBHOOK_EXAMPLE},
    {"category": "SUPPORT", "notification_target": _WEBHOOK_EXAMPLE},
]


def _headers(session_token: str) -> dict:
    return {
        "X-Bunq-Client-Authentication": session_token,
        "X-Bunq-Language": "en_US",
        "X-Bunq-Region": "nl_NL",
        "X-Bunq-Geolocation": "0 0 0 0 NL",
        "X-Bunq-Client-Request-Id": str(uuid.uuid4()),
        "User-Agent": "bunq-api-client/1.0",
        "Cache-Control": "no-cache",
        "Accept": "application/json",
    }


@router.get("/user/{user_id}/notification-filter-url", tags=["Notification Filters"])
def get_notification_filter_urls(user_id: int):
    """Retrieve all URL notification filters for a user."""
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{user_api_key_id}/notification-filter-url"
    response = requests.get(url, headers=_headers(session_token))
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    return response.json()


@router.post("/user/{user_id}/notification-filter-url", tags=["Notification Filters"])
def set_notification_filter_url(
    user_id: int,
    body: dict = Body(default={"notification_filters": _DEFAULT_FILTERS})
):
    """Manage the URL notification filters for a user."""
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{user_api_key_id}/notification-filter-url"
    response = requests.post(url, headers=_headers(session_token), data=json.dumps(body))
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    return response.json()


@router.put("/user/{user_id}/notification-filter-url", tags=["Notification Filters"])
def update_notification_filter_url(
    user_id: int,
    body: dict = Body(default={"notification_filters": _DEFAULT_FILTERS})
):
    """Manage the URL notification filters for a user."""
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{user_api_key_id}/notification-filter-url"
    response = requests.put(url, headers=_headers(session_token), data=json.dumps(body))
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    return response.json()


@router.get("/user/{user_id}/notification-filter-failure", tags=["Notification Filters"])
def get_notification_filter_failures(user_id: int):
    """Retrieve all URL notification failures for a user."""
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{user_api_key_id}/notification-filter-failure"
    response = requests.get(url, headers=_headers(session_token))
    print(response.headers)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    return response.json()

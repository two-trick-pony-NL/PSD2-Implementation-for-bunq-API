import requests
from fastapi import APIRouter, Body
from dependencies import BASE_URL, extract_session_info

router = APIRouter()


@router.get("/user/{user_id}/monetary-account/{account_id}/bunqme-tab/", tags=["bunqme"])
def get_bunqme_tabs(user_id: int, account_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"{BASE_URL}/v1/user/{end_user_id}/monetary-account/{account_id}/bunqme-tab",
        headers={
            "User-Agent": "bunq-python/1.0",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "application/json",
        },
    )
    return response.json()


@router.post("/user/{user_id}/monetary-account/{account_id}/bunqme-tab/", tags=["bunqme"])
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
        f"{BASE_URL}/v1/user/{end_user_id}/monetary-account/{account_id}/bunqme-tab",
        json=tab_entry,
        headers={
            "User-Agent": "bunq-python/1.0",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    return response.json()

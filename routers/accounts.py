import requests
from fastapi import APIRouter, Body
from dependencies import extract_session_info, BASE_URL

router = APIRouter()


@router.get("/user/{user_id}/", tags=["Userprofile"])
def get_user_info(user_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"{BASE_URL}/v1/user/{end_user_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "*/*"},
    )
    return response.json()


@router.get("/user/{user_id}/accounts", tags=["Monetary Accounts"])
def get_accounts(user_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"},
    )
    return response.json()


@router.get("/user/{user_id}/monetary-account/{monetary_account_id}", tags=["Monetary Accounts"])
def get_account(user_id: int, monetary_account_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"},
    )
    return response.json()


@router.post(
    "/user/{user_id}/monetary-account-bank",
    tags=["Monetary Accounts"],
    summary="Create a new monetary account",
)
def create_account(
    user_id: int,
    body: dict = Body(
        ...,
        example={
            "currency": "EUR",
            "description": "My savings account",
            "daily_limit": {"value": "1000.00", "currency": "EUR"},
        },
    ),
):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    payload = {"currency": body.get("currency", "EUR"), "description": body.get("description", "")}
    if "daily_limit" in body:
        payload["daily_limit"] = body["daily_limit"]
    response = requests.post(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account-bank",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"},
        json=payload,
    )
    return response.json()


@router.put(
    "/user/{user_id}/monetary-account-bank/{monetary_account_id}",
    tags=["Monetary Accounts"],
    summary="Update or deactivate a monetary account (set status to CANCELLED to deactivate)",
)
def update_account(
    user_id: int,
    monetary_account_id: int,
    body: dict = Body(
        ...,
        example={
            "description": "Updated account name",
            "daily_limit": {"value": "500.00", "currency": "EUR"},
            "status": "ACTIVE",
            "sub_status": "NONE",
            "reason": "OTHER",
            "reason_description": "No longer needed",
        },
    ),
):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    payload = {k: v for k, v in body.items() if v is not None}
    response = requests.put(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account-bank/{monetary_account_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"},
        json=payload,
    )
    return response.json()

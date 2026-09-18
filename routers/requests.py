import json
import requests
from fastapi import APIRouter, Body
from dependencies import extract_session_info, BASE_URL

router = APIRouter()


@router.get(
    "/user/{user_id}/monetary-account/{monetary_account_id}/request-inquiry",
    tags=["Requests"],
    summary="List all request inquiries for a monetary account",
)
def list_request_inquiries(user_id: int, monetary_account_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}/request-inquiry",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"},
    )
    return response.json()


@router.get(
    "/user/{user_id}/monetary-account/{monetary_account_id}/request-inquiry/{request_inquiry_id}",
    tags=["Requests"],
    summary="Get a single request inquiry",
)
def get_request_inquiry(user_id: int, monetary_account_id: int, request_inquiry_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}/request-inquiry/{request_inquiry_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"},
    )
    return response.json()


@router.post(
    "/user/{user_id}/monetary-account/{monetary_account_id}/request-inquiry",
    tags=["Requests"],
    summary="Create a request inquiry (request money from someone)",
)
def create_request_inquiry(
    user_id: int,
    monetary_account_id: int,
    body: dict = Body(
        ...,
        openapi_examples={"default": {"value": {
            "amount": "100.00",
            "currency": "EUR",
            "description": "You owe me!",
            "receiver_type": "EMAIL",
            "receiver_value": "sugardaddy@bunq.com",
            "receiver_name": "Sugar Daddy",
            "allow_bunqme": False,
        }}},
    ),
):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    payload = {
        "amount_inquired": {
            "value": body.get("amount", "0.00"),
            "currency": body.get("currency", "EUR"),
        },
        "counterparty_alias": {
            "type": body.get("receiver_type", "EMAIL"),
            "value": body.get("receiver_value", ""),
            "name": body.get("receiver_name", ""),
        },
        "description": body.get("description", ""),
        "allow_bunqme": body.get("allow_bunqme", False),
    }
    response = requests.post(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}/request-inquiry",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"},
        data=json.dumps(payload),
    )
    return response.json()


@router.put(
    "/user/{user_id}/monetary-account/{monetary_account_id}/request-inquiry/{request_inquiry_id}",
    tags=["Requests"],
    summary="Revoke a pending request inquiry (set status to REVOKED)",
)
def revoke_request_inquiry(
    user_id: int,
    monetary_account_id: int,
    request_inquiry_id: int,
):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.put(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}/request-inquiry/{request_inquiry_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"},
        data=json.dumps({"status": "REVOKED"}),
    )
    return response.json()
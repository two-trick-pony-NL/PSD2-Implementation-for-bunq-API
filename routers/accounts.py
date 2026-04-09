import requests
from fastapi import APIRouter
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

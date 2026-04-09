import requests
from typing import Dict, Any
from fastapi import APIRouter, Body
from dependencies import BASE_URL, extract_session_info

router = APIRouter()


@router.get("/user/{user_id}/cards", tags=["Cards"])
def list_cards(user_id: int):
    """[READ] Lists all cards for a given user."""
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{user_api_key_id}/card"
    headers = {
        "User-Agent": "FastAPI-Bunq-Wrapper",
        "X-Bunq-Client-Authentication": session_token,
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


@router.get("/user/{user_id}/card/{card_id}", tags=["Cards"])
def get_card_details(user_id: int, card_id: int):
    """[READ] Retrieves the details of a specific card."""
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{user_api_key_id}/card/{card_id}"
    headers = {
        "User-Agent": "FastAPI-Bunq-Wrapper",
        "X-Bunq-Client-Authentication": session_token,
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


@router.post("/user/{user_id}/credit-cards", tags=["Cards"], status_code=201)
def order_new_credit_card(
    user_id: int,
    first_line: str = Body("", description="The first line of the card."),
    second_line: str = Body("", description="The second line of the card.")):
    """[CREATE] Orders a new CREDIT card. NOTE: This call requires encryption."""
    from routers.accounts import get_user_info
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    print("Getting user info for display name...")
    user = get_user_info(user_id)
    user_display_name = user["Response"][0]["UserPerson"]["display_name"]
    print(f"User display name: {user_display_name}")

    url = f"{BASE_URL}/v1/user/{end_user_id}/card-debit"

    payload = {
        "second_line": second_line,
        "name_on_card": user_display_name,
        "type": "MASTERCARD",
        "product_type": "MASTERCARD_DEBIT",
        "order_status": "NEW_CARD_REQUEST_RECEIVED"
    }

    headers = {
        "User-Agent": "FastAPI-Bunq-Wrapper",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": "application/json",
    }

    print("Sending CREDIT card payload:", payload)
    response = requests.post(url, json=payload, headers=headers)
    return response.json()


@router.put("/user/{user_id}/card/{card_id}", tags=["Cards"])
def update_card(
    user_id: int,
    card_id: int,
    pin_code: str,
    card_limit_in_eur: str,
    card_limit_atm_in_eur: str,
    status: str,
) -> Dict[str, Any]:
    """
    [UPDATE] Updates a card with any combination of optional fields.
    NOTE: This call requires encryption.
    """
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    url = f"{BASE_URL}/v1/user/{user_api_key_id}/card/{card_id}"

    payload = {
        "pin_code": pin_code,
        "card_limit": {
            "value": card_limit_in_eur,
            "currency": "EUR"
        },
        "card_limit_atm": {
            "value": card_limit_atm_in_eur,
            "currency": "EUR"
        },
        "status": status,
    }

    headers = {
        "User-Agent": "FastAPI-Bunq-Wrapper",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": "application/json",
    }

    print("Sending final flexible PUT payload:", payload)
    response = requests.put(url, json=payload, headers=headers)

    if response.status_code >= 400:
        print("Error from bunq:", response.json())

    return response.json()

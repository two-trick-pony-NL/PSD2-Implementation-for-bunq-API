import json
import time
import requests
from datetime import datetime, timedelta
from fastapi import APIRouter, Body
from dependencies import extract_session_info, BASE_URL, bunq_client
from signing import sign_data

router = APIRouter()


@router.get("/user/{user_id}/payments/{monetary_account_id}", tags=["Payments"])
def get_payments(user_id: int, monetary_account_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)

    headers = {
        "User-Agent": "text",
        "X-Bunq-Client-Authentication": session_token,
        "Accept": "*/*",
    }

    url = f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}/payment"

    all_payments = []
    page = 0
    while url:
        print(f"Fetching page {page}")
        page = page + 1
        time.sleep(1)
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        payments = data.get("Response", [])
        all_payments.extend(payments)

        pagination = data.get("Pagination", {})
        older_url = pagination.get("older_url")

        # bunq returns relative URLs
        url = f"{BASE_URL}{older_url}" if older_url else None

    return {
        "count": len(all_payments),
        "payments": all_payments,
    }


@router.get("/user/{user_id}/monetary-account/{monetary_account_id}/draft-payment/{payment_id}/", tags=["Payments"])
def get_draft_payment(user_id: int, monetary_account_id: int, payment_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}/draft-payment/{payment_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "*/*"},
    )
    return response.json()


@router.get("/user/{user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/", tags=["Payments"])
def get_payment(user_id: int, monetary_account_id: int, payment_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)
    response = requests.get(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}/payment/{payment_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "*/*"},
    )
    return response.json()


@router.post(
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
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{body.get('monetary_account_id')}/draft-payment",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Content-Type": "application/json"
        },
        data=json.dumps(payload)
    )
    return response.json()


@router.put(
    "/user/{user_id}/monetary-account/{monetary_account_id}/draft-payment/{payment_id}/",
    tags=["Payments"],
    summary="Update draft payment status to ACCEPTED",
)
def update_draft_payment(user_id: int, monetary_account_id: int, payment_id: int):
    session_token, end_user_id, user_api_key_id = extract_session_info(user_id)

    payload = json.dumps({"status": "ACCEPTED"})
    signature = sign_data(payload, bunq_client.private_key_pem)

    headers = {
        "User-Agent": "text",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": "application/json",
        "X-Bunq-Client-Signature": signature
    }

    response = requests.put(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{monetary_account_id}/draft-payment/{payment_id}",
        headers=headers,
        data=payload
    )
    return response.json()


@router.post(
    "/user/{user_id}/payment",
    tags=["Payments"],
    summary="Create an immediate payment",
)
def create_payment(
    user_id: int,
    body: dict = Body(
        ...,
        example={
            "monetary_account_id": "2083712",
            "amount": "10.00",
            "currency": "EUR",
            "description": "Dinner split",
            "receiver_type": "EMAIL",
            "receiver_value": "sugardaddy@bunq.com",
            "receiver_name": "Best Friend",
        }
    )
):
    session_token, _, user_api_key_id = extract_session_info(user_id)

    payload = json.dumps({
        "amount": {
            "value": body.get("amount", "0.00"),
            "currency": body.get("currency", "EUR")
        },
        "counterparty_alias": {
            "type": body.get("receiver_type", "EMAIL"),
            "value": body.get("receiver_value", ""),
            "name": body.get("receiver_name", "")
        },
        "description": body.get("description", "")
    })
    signature = sign_data(payload, bunq_client.private_key_pem)

    headers = {
        "User-Agent": "text",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": "application/json",
        "X-Bunq-Client-Signature": signature
    }

    response = requests.post(
        f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{body.get('monetary_account_id')}/payment",
        headers=headers,
        data=payload
    )
    return response.json()


@router.post(
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
            f"{BASE_URL}/v1/user/{user_api_key_id}/monetary-account/{item.get('monetary_account_id')}/draft-payment",
            headers={
                "User-Agent": "text",
                "X-Bunq-Client-Authentication": session_token,
                "Content-Type": "application/json"
            },
            data=json.dumps(payload)
        )
        responses.append(response.json())

    return responses

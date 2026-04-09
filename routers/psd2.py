import json
import requests
from datetime import datetime, timedelta
from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import RedirectResponse
from dependencies import BASE_URL, bunq_client

router = APIRouter()


@router.post("/psd2/payment-service-provider-issuer-transaction", tags=["PSD2 User"])
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
            "url_redirect": "https://google.com",
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
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Content-Type": "application/json",
        "Accept": "*/*"
    }

    response = requests.post(
        f"{BASE_URL}/v1/user/{bunq_client.user_id}/payment-service-provider-issuer-transaction",
        headers=headers,
        data=json.dumps(payload)
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()


@router.get("/psd2/payment-service-provider-issuer-transaction/{transaction_id}", tags=["PSD2 User"])
def get_payment_service_provider_issuer_transaction(transaction_id: int):
    headers = {
        "Cache-Control": "no-cache",
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Content-Type": "application/json",
        "Accept": "*/*"
    }

    response = requests.get(
        f"{BASE_URL}/v1/user/{bunq_client.user_id}/payment-service-provider-issuer-transaction/{transaction_id}",
        headers=headers
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()


@router.get("/psd2/payment-service-provider-issuer-transaction-public/{public_id}", tags=["PSD2 User"])
def get_payment_service_provider_issuer_transaction_public(public_id: str):
    headers = {
        "Cache-Control": "no-cache",
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Content-Type": "application/json",
        "Accept": "*/*"
    }

    response = requests.get(
        f"{BASE_URL}/v1/user/{bunq_client.user_id}/payment-service-provider-issuer-transaction-public/{public_id}",
        headers=headers
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()


@router.get("/psd2/redirect/{public_id}", tags=["PSD2 User"])
def redirect_to_payment_service_provider_issuer_transaction(public_id: str):
    return RedirectResponse(url=f"https://psp.triage.bunq.com/?transactionId={public_id}")

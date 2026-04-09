import json
import uuid
import requests
from fastapi import APIRouter, Body, HTTPException
from dependencies import BASE_URL, bunq_client

router = APIRouter()


def _psd2_headers():
    return {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "X-Bunq-Language": "en_US",
        "X-Bunq-Region": "nl_NL",
        "X-Bunq-Geolocation": "0 0 0 0 NL",
        "X-Bunq-Client-Request-Id": str(uuid.uuid4()),
        "User-Agent": "bunq-api-client/1.0",
        "Cache-Control": "no-cache",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


@router.get("/credential-password-ip", tags=["IP Whitelist"])
def list_credential_password_ips():
    headers = {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Accept": "application/json",
    }
    response = requests.get(
        f"{BASE_URL}/v1/user/{bunq_client.user_id}/credential-password-ip",
        headers=headers
    )
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    return response.json()


@router.get("/credential-password-ip/{ip_id}", tags=["IP Whitelist"])
def get_credential_password_ip(ip_id: int):
    headers = {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Accept": "application/json",
    }
    response = requests.get(
        f"{BASE_URL}/v1/user/{bunq_client.user_id}/credential-password-ip/{ip_id}",
        headers=headers
    )
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    return response.json()


@router.get("/credential-password-ip/{credential_password_ip_id}/ip", tags=["IP Whitelist"])
def list_ips_for_credential(credential_password_ip_id: int):
    headers = {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Accept": "application/json",
    }
    response = requests.get(
        f"{BASE_URL}/v1/user/{bunq_client.user_id}/credential-password-ip/{credential_password_ip_id}/ip",
        headers=headers
    )
    return response.json()


@router.get("/credential-password-ip/{credential_password_ip_id}/ip/{item_id}", tags=["IP Whitelist"])
def get_ip_for_credential(credential_password_ip_id: int, item_id: int):
    headers = {
        "X-Bunq-Client-Authentication": str(bunq_client.session_token),
        "Accept": "application/json",
    }
    response = requests.get(
        f"{BASE_URL}/v1/user/{bunq_client.user_id}/credential-password-ip/{credential_password_ip_id}/ip/{item_id}",
        headers=headers
    )
    return response.json()


@router.post("/credential-password-ip/{credential_password_ip_id}/ip", tags=["IP Whitelist"])
def add_ip_for_credential(credential_password_ip_id: int, body: dict = Body(
    default={
        "ip": "*",
        "status": "ACTIVE"
    }
)):
    """
    Add a new IP to the list of allowed IPs for a credential-password-ip object.
    """
    payload = {
        "ip": body.get("ip", "*"),
        "status": body.get("status", "ACTIVE")
    }

    url = (
        f"{BASE_URL}/v1/user/{bunq_client.user_id}/"
        f"credential-password-ip/{credential_password_ip_id}/ip"
    )

    response = requests.post(url, headers=_psd2_headers(), data=json.dumps(payload))

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()


@router.put("/credential-password-ip/{credential_password_ip_id}/ip/{item_id}", tags=["IP Whitelist"])
def update_ip_status_for_credential(credential_password_ip_id: int, item_id: int, body: dict = Body(
    default={
        "status": "INACTIVE"
    }
)):
    """
    Update the status of an existing IP entry for a credential-password-ip.
    Only "status" is allowed here.
    """
    payload = {
        "status": body.get("status", "INACTIVE"),
    }

    url = (
        f"{BASE_URL}/v1/user/{bunq_client.user_id}/"
        f"credential-password-ip/{credential_password_ip_id}/ip/{item_id}"
    )

    response = requests.put(url, headers=_psd2_headers(), data=json.dumps(payload))

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    return response.json()

import requests
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from dependencies import BASE_URL, extract_session_info

router = APIRouter()


@router.post("/user/{user_id}/monetary-account/{monetary_account_id}/attachment", tags=["Attachments"])
async def create_monetary_account_attachment(
    user_id: int,
    monetary_account_id: int,
    file: UploadFile = File(..., description="The file to upload as an attachment."),
    description: str = Form(..., description="A brief description of the file.")
):
    """Creates a new attachment and immediately links it to a specific monetary account."""
    try:
        session_token, end_user_id, api_key_user_id = extract_session_info(user_id)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found or session invalid: {e}")

    file_content = await file.read()
    if not file_content:
        raise HTTPException(status_code=400, detail="The uploaded file cannot be empty.")

    headers = {
        "User-Agent": "FastAPI Bunq App",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": file.content_type,
        "X-Bunq-Attachment-Description": description,
    }

    url = f"{BASE_URL}/v1/user/{api_key_user_id}/monetary-account/{monetary_account_id}/attachment"

    response = requests.post(url, headers=headers, data=file_content)

    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Failed to create attachment on monetary account: {response.text}"
        )

    return response.json()


@router.post("/user/{user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-attachment", tags=["Attachments"])
def add_note_attachment_to_payment(
    user_id: int,
    monetary_account_id: int,
    payment_id: int,
    attachment_id: int = Form(..., description="The ID of the attachment to link."),
    description: str = Form(None, description="An optional description for the note-attachment.")
):
    """Adds an existing attachment to a payment as a 'note-attachment'."""
    session_token, end_user_id, api_key_user_id = extract_session_info(user_id)

    headers = {
        "User-Agent": "FastAPI Bunq App",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": "application/json"
    }

    request_body = {"attachment_id": attachment_id}
    if description:
        request_body["description"] = description

    url = f"{BASE_URL}/v1/user/{end_user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-attachment"

    response = requests.post(url, headers=headers, json=request_body)
    return response.json()


@router.get("/user/{user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-attachment", tags=["Attachments"])
def get_note_attachment_for_payment(
    user_id: int,
    monetary_account_id: int,
    payment_id: int,
):
    """Get note attachments for a payment."""
    session_token, end_user_id, api_key_user_id = extract_session_info(user_id)

    headers = {
        "User-Agent": "FastAPI Bunq App",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": "application/json"
    }

    url = f"{BASE_URL}/v1/user/{end_user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-attachment"

    response = requests.get(url, headers=headers)
    return response.json()


@router.post("/user/{user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-text", tags=["Attachments"])
def add_note_text_to_payment(
    user_id: int,
    monetary_account_id: int,
    payment_id: int,
    text: str = Form(None, description="A text note for this payment.")
):
    """Adds a text note to a payment."""
    session_token, end_user_id, api_key_user_id = extract_session_info(user_id)

    headers = {
        "User-Agent": "FastAPI Bunq App",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": "application/json"
    }

    url = f"{BASE_URL}/v1/user/{end_user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-text"

    response = requests.post(url, headers=headers, json={"content": text})
    return response.json()


@router.get("/user/{user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-text", tags=["Attachments"])
def get_note_text_for_payment(
    user_id: int,
    monetary_account_id: int,
    payment_id: int,
):
    """Get text notes for a payment."""
    session_token, end_user_id, api_key_user_id = extract_session_info(user_id)

    headers = {
        "User-Agent": "FastAPI Bunq App",
        "X-Bunq-Client-Authentication": session_token,
        "Content-Type": "application/json"
    }

    url = f"{BASE_URL}/v1/user/{end_user_id}/monetary-account/{monetary_account_id}/payment/{payment_id}/note-text"

    response = requests.get(url, headers=headers)
    return response.json()

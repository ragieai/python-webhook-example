import hashlib
import hmac
import json
import os

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel

load_dotenv()

app = FastAPI()

def validate_signature(secret_key: str, payload_body: bytes, received_signature: str) -> bool:
    """
    Validate the HMAC SHA-256 signature of the payload.

    :param secret_key: The shared secret key used for HMAC generation.
    :param payload_body: The raw request body in bytes.
    :param received_signature: The signature received in the 'X-Signature' header.
    :return: True if the signature is valid, False otherwise.
    """
    # Recompute the signature using the raw payload bytes
    expected_signature = hmac.new(
        secret_key.encode('utf-8'),
        payload_body,
        hashlib.sha256
    ).hexdigest()

    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected_signature, received_signature)

class WebhookPayload(BaseModel):
    type: str
    payload: dict

@app.post("/webhook")
async def handle_webhook(
    payload: WebhookPayload,
    request: Request,
):
    """
    Endpoint to handle incoming webhook requests.

    :param request: The incoming HTTP request.
    :return: A success message if the signature is valid.
    """
    received_signature = request.headers.get('X-Signature')
    if not received_signature:
        raise HTTPException(status_code=400, detail="Missing 'X-Signature' header")
    

    payload_body = await request.body()

    # Validate the signature
    if not validate_signature(os.getenv("WEBHOOK_SIGNING_SECRET"), payload_body, received_signature):
        # Signature mismatch; reject the request
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    print("Webhook received and verified successfully", payload.type, payload.payload)

    # Handle the webhook event as needed
    match payload.type:
        case "document_status_updated":
            # Handle event type 1
            pass
        case "document_deleted":
            # Handle event type 2
            pass
        case _:
            # Handle unknown event types
            pass

    return {"message": "Webhook received and verified successfully"}

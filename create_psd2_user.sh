#!/bin/bash

set -e

log() {
  echo -e "\n[INFO] $1"
}

error_exit() {
  echo -e "\n[ERROR] $1"
  exit 1
}

log "Generating installation key pair..."
openssl genrsa -out installation.key || error_exit "Failed to generate installation private key."
openssl rsa -in installation.key -outform PEM -pubout -out installation.pub || error_exit "Failed to generate installation public key."

log "Generating PSD2 certificate..."
openssl req -x509 -newkey rsa:4096 -keyout psd2.key -out psd2.cert -days 365 -nodes -subj "/CN=Test PISP AISP $(uuidgen)/C=NL" || error_exit "Failed to generate PSD2 certificate."

log "Creating installation..."
INSTALLATION=$(curl -s -X POST https://public-api.sandbox.bunq.com/v1/installation \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -H "X-Bunq-Client-Request-Id: $(uuidgen)" \
  --data "{\"client_public_key\": \"$(awk 'NF {sub(/\r/, ""); printf "%s\\n", $0;}' installation.pub)\"}") || error_exit "Installation creation failed."

log "Extracting installation token..."
TOKEN=$(echo $INSTALLATION | grep -o '"token":"[A-Za-z0-9]*"' | cut -d '"' -f 4) || error_exit "Failed to extract token."
echo -n "$TOKEN" > installation.token

log "Generating signature with PSD2 private key..."
openssl dgst -sign psd2.key -keyform PEM -sha256 -out signature <(cat installation.pub installation.token) || error_exit "Failed to generate signature."

log "Creating credential..."
CREDENTIAL=$(curl -s -X POST https://public-api.sandbox.bunq.com/v1/payment-service-provider-credential \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -H "X-Bunq-Client-Request-Id: $(uuidgen)" \
  -H "X-Bunq-Client-Authentication: $TOKEN" \
  --data "{\"client_payment_service_provider_certificate\": \"$(awk 'NF {sub(/\r/, ""); printf "%s\\n", $0;}' psd2.cert)\", \"client_payment_service_provider_certificate_chain\": \"$(awk 'NF {sub(/\r/, ""); printf "%s\\n", $0;}' psd2.cert)\", \"client_public_key_signature\": \"$(base64 < signature)\"}") || error_exit "Credential creation failed."

echo "$CREDENTIAL" > credential.json

log "Extracting credential token..."
CREDENTIAL_TOKEN=$(grep -o '"token_value":"[A-Za-z0-9]*"' credential.json | cut -d '"' -f 4) || error_exit "Failed to extract credential token."

log "Registering device..."
curl -s -X POST https://public-api.sandbox.bunq.com/v1/device-server \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -H "X-Bunq-Client-Request-Id: $(uuidgen)" \
  -H "X-Bunq-Client-Authentication: $TOKEN" \
  --data "{\"secret\":\"$CREDENTIAL_TOKEN\", \"description\": \"My server\"}" || error_exit "Device registration failed."

log "Preparing session request..."
SESSION_REQUEST_BODY="{\"secret\":\"$CREDENTIAL_TOKEN\"}"
echo -n "$SESSION_REQUEST_BODY" > session.request

log "Signing session request..."
openssl dgst -sign installation.key -keyform PEM -sha256 -out signature < session.request || error_exit "Failed to sign session request."
SESSION_REQUEST_SIGNATURE=$(base64 < signature)

log "Creating session..."
curl -s -X POST https://public-api.sandbox.bunq.com/v1/session-server \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -H "X-Bunq-Client-Request-Id: $(uuidgen)" \
  -H "X-Bunq-Client-Signature: $SESSION_REQUEST_SIGNATURE" \
  -H "X-Bunq-Client-Authentication: $TOKEN" \
  --data @"session.request" || error_exit "Session creation failed."


TOKEN_VALUE=$(jq -r '.Response[0].CredentialPasswordIp.token_value' credential.json)
echo -e "\n\nThis is your PSD2 user API key:"
echo "$TOKEN_VALUE"

rm -f installation.key installation.pub psd2.key psd2.cert signature credential.json session.request session.response.json installation.token .env


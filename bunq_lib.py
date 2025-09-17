import json
import requests
from signing import generate_rsa_key_pair, sign_data, verify_response
import uuid


class BunqOauthClient:
    def __init__(self, api_key, service_name, base_url="https://public-api.sandbox.bunq.com/v1"):
        self.service_name = service_name
        self.api_key = api_key
        self.private_key_pem, self.public_key_pem = generate_rsa_key_pair()
        self.device_token = None
        self.server_public_key = None
        self.device_server_id = None
        self.session_token = None
        self.user_id = None
        self.base_url = base_url

        # Try to load device token from file
        self.load_device_token()

    def save_device_token(self):
        """Save the device token to a file."""
        with open('device_token.json', 'w') as file:
            json.dump({"device_token": self.device_token}, file)

    def load_device_token(self):
        """Load the device token from a file if it exists."""
        try:
            with open('device_token.json', 'r') as file:
                data = json.load(file)
                self.device_token = data.get("device_token")
                print(f"bunq - Loaded device token from file [KEEP THIS SAFE!]")
        except FileNotFoundError:
            print("bunq - No device token found, need to create a new one.")

    def create_installation(self):
        """
        https://doc.bunq.com/tutorials/your-first-payment/creating-the-api-context0oµ∆≤≥ydtr
        :return:
        """
        if self.device_token is not None:
            print("bunq - Device token already created.")
            return

        url = f"{self.base_url}/installation"
        payload = json.dumps({"client_public_key": self.public_key_pem})

        headers = {
            'Content-Type': 'application/json',
            'User-Agent': self.service_name,
            'X-Bunq-Language': 'en_US',
            'X-Bunq-Region': 'nl_NL',
            'X-Bunq-Geolocation': '0 0 0 0 000',
        }

        response = requests.post(url, headers=headers, data=payload)
        data = response.json()

        self.device_token = next(item["Token"]["token"] for item in data["Response"] if "Token" in item)
        self.server_public_key = next(
            item["ServerPublicKey"]["server_public_key"] for item in data["Response"] if "ServerPublicKey" in item)
        self.save_device_token()  # Save the token for future use

    def create_device_server(self):
        if self.device_server_id is not None:
            print("bunq - Device server already created.")
            return
        if not self.device_token:
            print("bunq - Device token is required to create device server.")

            return

        url = f"{self.base_url}/device-server"
        payload = json.dumps({
            "description": self.service_name,
            "secret": self.api_key,
            "permitted_ips": ['*']
        })
        signed_payload_signature = sign_data(payload, self.private_key_pem)

        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'User-Agent': self.service_name,
            'X-Bunq-Language': 'en_US',
            'X-Bunq-Region': 'nl_NL',
            'X-Bunq-Geolocation': '0 0 0 0 000',
            'X-Bunq-Client-Authentication': self.device_token,
            'X-Bunq-Client-Signature': signed_payload_signature
        }
        response = requests.post(url, headers=headers, data=payload)
        self.device_server_id = response.text

    def create_session(self):
        if not self.device_token:
            print("bunq - Device token is required to create session.")
            print("\n\nGo to http://localhost:8000/setup_one_time to initiate setup\n\n")

            return

        url = f"{self.base_url}/session-server"
        payload_dict = {"secret": self.api_key}
        payload_json = json.dumps(payload_dict, separators=(',', ':'))
        signed_payload_signature = sign_data(payload_json, self.private_key_pem)

        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'User-Agent': self.service_name,
            'X-Bunq-Language': 'en_US',
            'X-Bunq-Region': 'nl_NL',
            'X-Bunq-Geolocation': '0 0 0 0 000',
            'X-Bunq-Client-Authentication': self.device_token,
            'X-Bunq-Client-Signature': signed_payload_signature
        }

        response = requests.post(url, headers=headers, data=payload_json)
        data = response.json()
        print(data)
        # Extract and save session token
        self.session_token = next(item["Token"]["token"] for item in data["Response"] if "Token" in item)
        user_keys = ["UserPaymentServiceProvider", "UserPerson", "UserCompany"]
        self.user_id = next(
            item[key]["id"]
            for item in data["Response"]
            for key in user_keys
            if key in item
        )
        print(f"bunq - Session Token: {self.session_token}")
        print(f"bunq - User ID: {self.user_id}")

    def create_oauth_client(self, endpoint: str, method: str = "POST"):
        url = f"{self.base_url}/user/{self.user_id}/{endpoint}"
        print(f"[DEBUG] bunq - Requesting: {method} {url}")

        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'User-Agent': self.service_name,
            'X-Bunq-Language': 'en_US',
            'X-Bunq-Region': 'nl_NL',
            'X-Bunq-Geolocation': '0 0 0 0 000',
            'X-Bunq-Client-Authentication': self.session_token,
            'X-Bunq-Client-Request-Id': str(uuid.uuid4())
        }

        payload = json.dumps([], separators=(',', ':'))
        headers["X-Bunq-Client-Signature"] = sign_data(payload, self.private_key_pem)

        def do_request(method, url):
            return requests.request(method, url, headers=headers, data=payload if method == "POST" else None)

        response = do_request(method, url)
        print(f"[DEBUG] Initial response status: {response.status_code}")

        if response.status_code == 401:
            print("[WARNING] Unauthorized (401) - refreshing session and retrying")
            self.refresh_session()
            headers['X-Bunq-Client-Authentication'] = self.session_token
            headers['X-Bunq-Client-Request-Id'] = str(uuid.uuid4())
            headers["X-Bunq-Client-Signature"] = sign_data(payload, self.private_key_pem)
            response = do_request(method, url)
            print(f"[DEBUG] Retried response status: {response.status_code}")

        if response.status_code not in [200, 201]:
            print(f"[WARNING] {response.status_code} - {response.text}")
            raise Exception(f"Failed to create OAuth client")

        response_body = response.text
        server_signature = response.headers.get('X-Bunq-Server-Signature')

        if server_signature and self.server_public_key:
            if not verify_response(response_body, server_signature, self.server_public_key):
                raise Exception("Response signature verification failed")
            print("[DEBUG] Response signature verified")

        try:
            data = response.json()
            if "OauthClient" in data['Response'][0]:
                oauth = data['Response'][0]['OauthClient']
            else:
                # fallback GET
                response = do_request("GET", url)
                data = response.json()
                oauth = data['Response'][0]['OauthClient']

            client_id = oauth['client_id']
            secret = oauth['secret']
            database_id = oauth['id']

            print(f"[DEBUG] OAuth Client ID: {client_id}")
            print(f"[DEBUG] OAuth Secret: {secret}")
            print(f"[DEBUG] OAuth DB ID: {database_id}")
            return client_id, secret, database_id

        except Exception as e:
            print(f"[ERROR] Failed to extract OAuth client info: {e}")
            return None, None, None

    def get_oauth_client(self, client_id: str):
        url = f"{self.base_url}/user/{self.user_id}/oauth-client/{client_id}"
        print(url)

        # Default headers
        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'User-Agent': self.service_name,
            'X-Bunq-Language': 'en_US',
            'X-Bunq-Region': 'nl_NL',
            'X-Bunq-Geolocation': '0 0 0 0 000',
            'X-Bunq-Client-Authentication': self.session_token,
            'X-Bunq-Client-Request-Id': str(uuid.uuid4())  # Should be unique for each request
        }
        response = requests.request("GET", url, headers=headers)
        data = json.loads(response.text)
        print(data)

        client = data['Response'][0]['OauthClient']
        client_id = client['id']
        secret = client['secret']
        print(f"[DEBUG] Oauth Client ID: {client_id}")
        print(f"[DEBUG] Oauth Client Secret: {secret}")
        print(f"[DEBUG] Oauth Client: {response.text}")
        return client_id, secret

    def add_oauth_callback_url(self, client_id: str, callback_url: str):
        url = f"{self.base_url}/user/{self.user_id}/oauth-client/{client_id}/callback-url"
        print(f"[DEBUG] Adding callback URL: POST {url}")

        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'User-Agent': self.service_name,
            'X-Bunq-Language': 'en_US',
            'X-Bunq-Region': 'nl_NL',
            'X-Bunq-Geolocation': '0 0 0 0 000',
            'X-Bunq-Client-Authentication': self.session_token,
            'X-Bunq-Client-Request-Id': str(uuid.uuid4())
        }

        payload = {
            "url": callback_url
        }

        json_payload = json.dumps(payload, separators=(',', ':'))
        signed_payload_signature = sign_data(json_payload, self.private_key_pem)
        headers["X-Bunq-Client-Signature"] = signed_payload_signature
        response = requests.post(url, headers=headers, data=json_payload)
        print(f"[DEBUG] Callback URL POST Status Code: {response.status_code}")
        print(f"[DEBUG] Callback URL POST Response: {response.text}")
        return json.loads(response.text)

    def get_end_user_session_token(self, user_oauth_token):
        url = f"{self.base_url}/session-server"
        payload_dict = {"secret": user_oauth_token}
        payload_json = json.dumps(payload_dict, separators=(',', ':'))
        signed_payload_signature = sign_data(payload_json, self.private_key_pem)

        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'User-Agent': self.service_name,
            'X-Bunq-Language': 'en_US',
            'X-Bunq-Region': 'nl_NL',
            'X-Bunq-Geolocation': '0 0 0 0 000',
            'X-Bunq-Client-Authentication': self.device_token,
            'X-Bunq-Client-Signature': signed_payload_signature
        }

        response = requests.post(url, headers=headers, data=payload_json)
        data = response.json()
        return data.get("Response")[1].get('Token').get('token')

    def get_end_user_oauth_details(self, user_oauth_token):
        url = f"{self.base_url}/session-server"
        payload_dict = {"secret": user_oauth_token}
        payload_json = json.dumps(payload_dict, separators=(',', ':'))
        signed_payload_signature = sign_data(payload_json, self.private_key_pem)

        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'User-Agent': self.service_name,
            'X-Bunq-Language': 'en_US',
            'X-Bunq-Region': 'nl_NL',
            'X-Bunq-Geolocation': '0 0 0 0 000',
            'X-Bunq-Client-Authentication': self.device_token,
            'X-Bunq-Client-Signature': signed_payload_signature
        }

        response = requests.post(url, headers=headers, data=payload_json)
        #print(response.json())
        return response.json()



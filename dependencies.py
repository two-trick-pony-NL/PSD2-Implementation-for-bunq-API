import os
import requests
from dotenv import load_dotenv
from bunq_lib import BunqOauthClient
from db import get_user

load_dotenv()

YOUR_API_KEY = "43389182a0dc25480c4ce0feb4045166194d6bbcc423175ccb8247ca601df186"

REDIRECT_URI = "https://localhost:8000/callback"
BUNQ_AUTH_URL = "https://oauth.sandbox.bunq.com/auth"
BUNQ_TOKEN_URL = "https://api-oauth.sandbox.bunq.com/v1/token"
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", None)
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", None)
USER_API_KEY = os.getenv("USER_API_KEY", YOUR_API_KEY)

BASE_URL = "https://public-api.sandbox.bunq.com"

bunq_client = BunqOauthClient(USER_API_KEY, service_name='PSD2 Example Script')
bunq_client.create_session()


def extract_session_info(user_id: int):
    user = get_user(user_id)
    oauth_user = bunq_client.get_end_user_oauth_details(user.access_token)
    session_token = oauth_user["Response"][1]["Token"]["token"]
    end_user_id = oauth_user["Response"][2]["UserApiKey"]["granted_by_user"]["UserPerson"]["id"]
    user_api_key = oauth_user["Response"][2]["UserApiKey"]["id"]
    return session_token, end_user_id, user_api_key
import time
import requests
from fastapi import FastAPI
from fastapi.responses import RedirectResponse, HTMLResponse
from dotenv import load_dotenv
from db import init_db
from utils import log_request
from dependencies import bunq_client, REDIRECT_URI, YOUR_API_KEY
from routers import oauth, accounts, payments, requests as request_router, psd2, ip_whitelist, notifications, bunqme, attachments, events, cards

load_dotenv()

# Patch the Session.request method globally
requests.Session.request = log_request

app = FastAPI(
    title="bunq API Example",
    description="""
Welcome to the **bunq API Example** This implementation is aimed at demonstrating how to use bunq's OAuth2 flow and interact with their API using FastAPI.
Refer to the readme.md to see how to get the setup working. Each of these endpoints allows you to interact with bunq's API in the role of PSD2 user on behalf of a bunq user after completing the OAuth2 authorization process.

refer to https://doc.bunq.com for all API documentation

""",
    version="1.0.0"
)

app.include_router(oauth.router)
app.include_router(accounts.router)
app.include_router(payments.router)
app.include_router(request_router.router)
app.include_router(psd2.router)
app.include_router(ip_whitelist.router)
app.include_router(notifications.router)
app.include_router(bunqme.router)
app.include_router(attachments.router)
app.include_router(events.router)
app.include_router(cards.router)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def read_root():
    return RedirectResponse(url="/docs")


@app.get("/setup_one_time", response_class=HTMLResponse, include_in_schema=False)
def setup_one_time():
    print("\n Setting up Bunq OAuth")

    print("-> Step 0: Setting up mock database")
    init_db()

    print("-> Step 1: Creating Installation")
    bunq_client.create_installation()
    time.sleep(3)

    print("-> Step 2: Creating Device Server")
    bunq_client.create_device_server()
    time.sleep(3)

    print("-> Step 3: Creating Session")
    bunq_client.create_session()
    time.sleep(3)

    print("-> Step 4: Creating OAuth Client")
    oauth_client_id, oauth_secret, oauth_database_id = bunq_client.create_oauth_client(endpoint="oauth-client", method="POST")
    time.sleep(3)

    print("-> Step 5: Registering Callback URL")
    bunq_client.add_oauth_callback_url(client_id=oauth_database_id, callback_url=REDIRECT_URI)
    time.sleep(3)

    print("-> Step 6: Adding Credentials to .env file")
    filepath = ".env"
    values = {
        "OAUTH_CLIENT_ID": oauth_client_id,
        "OAUTH_CLIENT_SECRET": oauth_secret,
        "USER_API_KEY": YOUR_API_KEY,
    }
    with open(filepath, "w") as f:
        for key, value in values.items():
            f.write(f"{key}={value}\n")
    print(f"[INFO] .env file created at {filepath}")

    html_content = f"""
        <html>
            <body>
                <h2>Done -- bunq Oauth Client set up</h2>
                <p>Set <code>OAUTH_CLIENT_ID='{oauth_client_id}'</code> and <code>OAUTH_CLIENT_SECRET='{oauth_secret}'</code> in your config.</p>
                <ul>
                    <li>Restart the FastAPI server</li>
                    <li>Remove the setup code</li>
                    <li>Remove the API key (It's been transferred to a <code>.env</code> file)</li>
                </ul>
            </body>
        </html>
        """
    return HTMLResponse(content=html_content)

# PSD2 User Setup & API Key Integration

## Intro
This repository provides an example implementation of the PSD2 protocol using the bunq API. By running this code, you can gain access to bunq users’ accounts—granted when they authorize access by scanning a QR code.

## Security and certificates
> 💡 Note: You may need formal certification to access user payment data. This code is only a basic example showing how to request OAuth credentials and use them. It is not production-ready.

## What is PSD2 What can I do with it?
PSD2 (Payment Services Directive 2) is a European regulation aimed at making payments safer, boosting innovation, and increasing competition in financial services. It requires banks to open up their payment infrastructure and customer data (with consent) to third-party providers via secure APIs.

**What can you do with PSD2?**

* **Access Account Information:** With user permission, you can read bank account details, transactions, balances, and payment history.
* **Initiate Payments:** You can create payment requests or initiate payments on behalf of users.

In short, PSD2 lets developers build innovative, secure financial apps that interact directly with users’ bank accounts — all while protecting user consent and privacy.


## What are the moving parts in this installation 
This example is written in Python using the FastAPI framework. We connect the following entities: 
#### bunq 
bunq is the bank that holds all the financial records for their users and exposes the API endpoints to interact with financial records (given you have authorization)
#### end-user 
These are bunq users and users of your app. The idea is that these bunq users will connect their bunq account to your app through the oauth protocol

#### The app //  PSD2 provider // you
In this example the Fastapi implementation acts as the PSD2 provider. You can use the examples in this code to build your own implementation. 
In the app itself we have a few more moving parts: 
- a database - used in this example to store access tokens from bunq users that granted access
- private and public certificates that handle authentication
- a PSD2 certificate. in `create_psd2_user.sh` we handle user creation for you but you'll have to manage this yourself for production

## Setup Instructions
1. **Make the setup script executable**

```bash
chmod +x create_psd2_user.sh
```
This allows us to run the script that creates a new user for you in the next step

2. **Run the script to generate your PSD2 user and fetch the API key**

```bash
./create_psd2_user.sh
```
This creates a PSD2 user and registers it's certificates with bunq. After that it posts a API key to the console.
In production you want to hang on to the other information (e.g. user id) that this script prints out but it's not needed for this demo. 

3. **Copy the printed API key**

Add the API key to your main.py in the `YOUR_API_KEY=` 

4. **Install Fastapi dependancies**
```commandline
pip install -r requirements.txt
```

5. **Run the server**
```commandline
uvicorn main:app --reload
```

6. **The command line will tell you to go to:  http://localhost:8000/setup_one_time **
This will trigger a few things to be initialized in bunq this only needs to be run once. This may take a minute.

This script completes these steps: 
- It initializes the database (which the demo application depends on)
- It handles the Installation and Device registration for your app with bunq. This is part of creating the API context. Read more about that here: https://doc.bunq.com/tutorials/your-first-payment/creating-the-api-context
- It creates the first session for your app 
- It then creates a oauth client 
- It adds a callback URL to the oauth client (where the user is to be redirected after completing oauth)
- It generates a .env file that stores the oauth credentials

7. **Restart the FastAPI server**
This allows it to load the .env file that was just created
8. **Done! Now let's grant access to the bunq account of a user:**
- Go to `localhost:8000/auth` to initiate a oauth session. You'll be redirected to bunq
- You can scan the QR code - if you don't have the sandbox app you can grab it here: https://doc.bunq.com/getting-started/tools/android-emulator
- If you cannot run the bunq sandbox app on a physical device then you can also copy paste it on a virtual device
- In the app grant access for all bank accounts you want to grant access too 
- You'll be redirected to your callback URL. You may have to change `https` to `http` if you run on localhost
- You should see something like `{"message":"OAuth success","new_user_id":6}` this means that the database now contains a user with id `6` that has a valid access token associated with it that grants the app access to bunq

  <img width="721" alt="Screenshot 2025-05-26 at 12 59 26 PM" src="https://github.com/user-attachments/assets/cfea9651-f5e7-4286-9cc8-36282913a18b" />


9. **Get access to a users information** 
- Simply go to `localhost:8000/docs` this is a swagger interface for the fastapi server we just buit. 
- You could now go to your `localhost:8000/users/6` endpoint to see the user profile of that user. In the background this happens:
  - The user API key is retrieved from our local database
  - This API key is used to create a user session token 
  - This session token can be used in API calls to bunq 
  - So in the example of `/users/6` a calls is made 
```commandline
response = requests.get(
        f"https://public-api.sandbox.bunq.com/v1/user-person/{end_user_id}",
        headers={
            "User-Agent": "text",
            "X-Bunq-Client-Authentication": session_token,
            "Accept": "*/*"},
    )
```
Which returns the details of that user.

10. **Advanced calls**
Other API calls work the same way. Fetch user token, get a session make a call. However you can also create payments and requests. See the `/docs/` page to see what is possible and also to see what parameters are required.

<img width="1365" alt="Screenshot 2025-05-26 at 12 58 52 PM" src="https://github.com/user-attachments/assets/ce19155f-9faf-4655-a0db-e21aa388d966" />


# Implemented calls: 
By now I added quite some endpoints to this set up Currently we have: 
| Method | Endpoint                                                               | Used For                                                        |
|--------|------------------------------------------------------------------------|-----------------------------------------------------------------|
| GET    | /auth                                                                  | Start OAuth authorization flow                                  |
| GET    | /callback                                                              | OAuth callback to exchange code for access token               |
| GET    | /user/{user_id}/                                                       | Get basic user info                                             |
| GET    | /user/{user_id}/accounts                                               | Get list of user’s monetary accounts                            |
| GET    | /user/{user_id}/payments/{monetary_account_id}                        | Get payments for a monetary account                             |
| POST   | /user/{user_id}/request-inquiry                                       | Create a payment request inquiry                                |
| POST   | /user/{user_id}/draft-payment                                          | Create a draft payment                                          |
| POST   | /psd2/payment-service-provider-issuer-transaction                     | Create a PSD2 payment service provider issuer transaction       |
| GET    | /psd2/payment-service-provider-issuer-transaction/{transaction_id}    | Get details of a PSD2 payment service provider issuer transaction |
| GET    | /psd2/payment-service-provider-issuer-transaction-public/{public_id}  | Get public info of a PSD2 payment service provider issuer transaction |
| GET    | /credential-password-ip                                                | List all credential-password-ip objects                         |
| GET    | /credential-password-ip/{ip_id}                                        | Get a specific credential-password-ip object                    |
| GET    | /credential-password-ip/{credential_password_ip_id}                   | Get credential-password-ip details                              |
| GET    | /credential-password-ip/{credential_password_ip_id}/ip                | List IP whitelist entries for a credential                      |
| POST   | /credential-password-ip/{credential_password_ip_id}/ip                | Add a new IP to whitelist for a credential                      |
| GET    | /credential-password-ip/{credential_password_ip_id}/ip/{item_id}      | Get details of a specific IP whitelist entry                    |
| PUT    | /credential-password-ip/{credential_password_ip_id}/ip/{item_id}      | Update status of an IP whitelist entry (e.g., ACTIVE/INACTIVE)  |

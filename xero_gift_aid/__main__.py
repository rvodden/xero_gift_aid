import pkce
from urllib.parse import urlunsplit, urlencode
import requests

from xero_python.api_client import ApiClient, Configuration
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.accounting import AccountingApi
from xero_python.exceptions import AccountingBadRequestException


REDIRECT_URL = "http://localhost:8026"
CLIENT_ID = "3B60562227C14D2EAA9D6A1F5094AF6E"


def get_authorization_url(code_challenge: str, redirect_url: str) -> str:
    query = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_url,
        "scope": " ".join(["offline_access", "accounting.contacts.read"]),
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    return urlunsplit(
        ["https", "login.xero.com", "identity/connect/authorize", urlencode(query), ""]
    )


def exchange_code_for_access_token(code: str, code_verifier: str, redirect_url: str):
    exchange_url = "https://identity.xero.com/connect/token"
    response = requests.post(
        exchange_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": redirect_url,
            "code_verifier": code_verifier,
        },
    )
    return response.json()['access_token']


if __name__ == "__main__":
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    print("Please visit the following URL:")
    print(get_authorization_url(code_challenge, REDIRECT_URL))
    code = input("Please enter the code from the redirect URL: ")
    token = exchange_code_for_access_token(code, code_verifier, REDIRECT_URL)

    api_client = ApiClient(Configuration(
        debug=True,
        oauth2_token=OAuth2Token(
            client_id=CLIENT_ID,
            client_secret=token
        )
    ), pool_threads=1)

    @api_client.oauth2_token_getter
    def obtain_xero_auth2_token():
        return token
    
    @api_client.oauth2_token_saver
    def store_xero_auth2_token(_token):
        global token
        token = _token

    accounting_client = AccountingApi(api_client)

    try:
        contacts_read = accounting_client.get_contacts('')
    except AccountingBadRequestException as accounting_bad_request_exception:
        print(accounting_bad_request_exception)

    print(contacts_read)

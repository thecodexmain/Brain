"""
Braintree card-tokenizer API.
Wraps the kaffn8/Braintree add-payment-method flow behind an HTTP API.
Deploy target: Railway.
"""

import os
import re
import json
import base64
import uuid
import logging
from typing import Optional

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, Field

# ---------------------------------------------------------------- config

API_KEY = os.environ.get("API_KEY", "")  # optional bearer for the service itself
SITE_BASE = os.environ.get("SITE_BASE", "https://www.kaffn8.com").rstrip("/")
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "30"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
)
log = logging.getLogger("cardtok")

app = FastAPI(title="Card Tokenizer API", version="1.0.0")


# ---------------------------------------------------------------- models

class CardIn(BaseModel):
    number: str = Field(..., min_length=12, max_length=19)
    expiration_month: str = Field(..., min_length=1, max_length=2)
    expiration_year: str = Field(..., min_length=2, max_length=4)
    cvv: str = Field(..., min_length=3, max_length=4)


class AccountIn(BaseModel):
    username: str
    password: str


class AddCardIn(BaseModel):
    account: AccountIn
    card: CardIn
    card_type: str = "visa"
    device_data_correlation_id: Optional[str] = None


class AddCardOut(BaseModel):
    ok: bool
    token: Optional[str] = None
    woo_nonce: Optional[str] = None
    auth_fingerprint: Optional[str] = None
    raw_status_code: int
    message: str


# ---------------------------------------------------------------- auth dep

def require_api_key(authorization: Optional[str] = Header(default=None)):
    if not API_KEY:
        return  # auth disabled
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    if authorization.split(" ", 1)[1].strip() != API_KEY:
        raise HTTPException(status_code=401, detail="invalid bearer token")


# ---------------------------------------------------------------- flow

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/154.0.0.0 Safari/537.36"
)

SEC_CH_UA = '"Chromium";v="154", "Brave";v="154", "Not A(Brand";v="99"'


def _base_headers() -> dict:
    return {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.5",
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-gpc": "1",
        "user-agent": UA,
    }


def run_flow(account: AccountIn, card: CardIn, card_type: str,
             device_data_correlation_id: Optional[str]) -> AddCardOut:
    session = requests.Session()
    session.headers.update(_base_headers())

    # ---- 1. GET /my-account/ -> login nonce
    h1 = _base_headers()
    h1.update({
        "cache-control": "max-age=0",
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })
    r1 = session.get(f"{SITE_BASE}/my-account/", headers=h1, timeout=REQUEST_TIMEOUT)
    soup = BeautifulSoup(r1.text, "html.parser")
    login_nonce_el = soup.find("input", {"name": "woocommerce-login-nonce"})
    if not login_nonce_el:
        raise HTTPException(status_code=502, detail="login nonce not found (site layout changed or blocked)")
    lnonce = login_nonce_el["value"]

    # ---- 2. POST login
    h2 = _base_headers()
    h2.update({
        "cache-control": "max-age=0",
        "content-type": "application/x-www-form-urlencoded",
        "origin": SITE_BASE,
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })
    data_login = {
        "username": account.username,
        "password": account.password,
        "rememberme": "forever",
        "woocommerce-login-nonce": lnonce,
        "_wp_http_referer": "/my-account/",
        "login": "Log in",
    }
    r2 = session.post(f"{SITE_BASE}/my-account/", headers=h2, data=data_login, timeout=REQUEST_TIMEOUT)
    if "woocommerce-error" in r2.text and "logged" not in r2.text.lower():
        # best-effort login failure detection
        raise HTTPException(status_code=401, detail="login failed")

    # ---- 3. GET add-payment-method page -> woo nonce + client token nonce
    h3 = _base_headers()
    h3.update({
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/payment-methods/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })
    r3 = session.get(f"{SITE_BASE}/my-account/add-payment-method/", headers=h3, timeout=REQUEST_TIMEOUT)
    soup3 = BeautifulSoup(r3.text, "html.parser")

    woo_nonce_el = soup3.find("input", {"name": "woocommerce-add-payment-method-nonce"})
    if not woo_nonce_el:
        raise HTTPException(status_code=502, detail="woo add-payment-method nonce not found")
    woo_nonce = woo_nonce_el["value"]

    m = re.search(r'"client_token_nonce"\s*:\s*"([^"]+)"', r3.text)
    if not m:
        raise HTTPException(status_code=502, detail="client_token_nonce not found on page")
    client_token_nonce = m.group(1)

    # ---- 4. AJAX -> get braintree client token
    h4 = _base_headers()
    h4.update({
        "accept": "*/*",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "origin": SITE_BASE,
        "priority": "u=1, i",
        "referer": f"{SITE_BASE}/my-account/add-payment-method/",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-requested-with": "XMLHttpRequest",
    })
    data4 = {
        "action": "wc_braintree_credit_card_get_client_token",
        "nonce": client_token_nonce,
    }
    r4 = session.post(f"{SITE_BASE}/wp-admin/admin-ajax.php", headers=h4, data=data4, timeout=REQUEST_TIMEOUT)
    try:
        ajax_json = r4.json()
    except Exception:
        raise HTTPException(status_code=502, detail="admin-ajax returned non-json")

    data_field = ajax_json.get("data")
    if isinstance(data_field, str):
        client_token = data_field
    elif isinstance(data_field, dict):
        client_token = data_field.get("clientToken")
    else:
        client_token = None

    if not client_token:
        raise HTTPException(status_code=502, detail=f"clientToken missing in ajax response: {ajax_json}")

    token_data = json.loads(base64.b64decode(client_token))
    auth_fingerprint = token_data["authorizationFingerprint"]

    # ---- 5. Braintree graphql tokenize
    session_id = str(uuid.uuid4())
    correlation_id = device_data_correlation_id or session_id[:32]

    h5 = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.5",
        "authorization": f"Bearer {auth_fingerprint}",
        "braintree-version": "2018-05-10",
        "content-type": "application/json",
        "origin": "https://assets.braintreegateway.com",
        "priority": "u=1, i",
        "referer": "https://assets.braintreegateway.com/",
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
        "sec-gpc": "1",
        "user-agent": UA,
    }

    # normalize year to 4 digits if caller passed 2
    year = card.expiration_year
    if len(year) == 2:
        year = "20" + year
    month = card.expiration_month.zfill(2)

    gql = {
        "clientSdkMetadata": {
            "source": "client",
            "integration": "custom",
            "sessionId": session_id,
        },
        "query": (
            "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { "
            "  tokenizeCreditCard(input: $input) { "
            "    token "
            "    creditCard { "
            "      bin brandCode last4 cardholderName expirationMonth expirationYear "
            "      binData { prepaid healthcare debit durbinRegulated commercial payroll "
            "        issuingBank countryOfIssuance productId business consumer purchase corporate } "
            "    } "
            "  } "
            "}"
        ),
        "variables": {
            "input": {
                "creditCard": {
                    "number": card.number,
                    "expirationMonth": month,
                    "expirationYear": year,
                    "cvv": card.cvv,
                },
                "options": {"validate": False},
            }
        },
        "operationName": "TokenizeCreditCard",
    }

    r5 = session.post("https://payments.braintree-api.com/graphql", headers=h5, json=gql, timeout=REQUEST_TIMEOUT)
    try:
        r5_json = r5.json()
    except Exception:
        raise HTTPException(status_code=502, detail=f"braintree non-json: {r5.text[:200]}")

    if "errors" in r5_json:
        return AddCardOut(
            ok=False, raw_status_code=r5.status_code,
            message=f"braintree graphql error: {r5_json['errors']}",
        )

    try:
        token = r5_json["data"]["tokenizeCreditCard"]["token"]
    except Exception:
        return AddCardOut(
            ok=False, raw_status_code=r5.status_code,
            message=f"token missing in braintree response: {str(r5_json)[:300]}",
        )

    # ---- 6. POST add-payment-method with the nonce
    h6 = _base_headers()
    h6.update({
        "cache-control": "max-age=0",
        "content-type": "application/x-www-form-urlencoded",
        "origin": SITE_BASE,
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/add-payment-method/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })

    device_data = json.dumps({"correlation_id": correlation_id})

    data6 = [
        ("payment_method", "braintree_credit_card"),
        ("wc-braintree-credit-card-card-type", card_type),
        ("wc-braintree-credit-card-3d-secure-enabled", ""),
        ("wc-braintree-credit-card-3d-secure-verified", ""),
        ("wc-braintree-credit-card-3d-secure-order-total", "0.00"),
        ("wc_braintree_credit_card_payment_nonce", token),
        ("wc_braintree_device_data", device_data),
        ("wc-braintree-credit-card-tokenize-payment-method", "true"),
        ("wc_braintree_paypal_payment_nonce", ""),
        ("wc-braintree-paypal-context", "shortcode"),
        ("wc_braintree_paypal_amount", "0.00"),
        ("wc_braintree_paypal_currency", "USD"),
        ("wc_braintree_paypal_locale", "en_us"),
        ("wc-braintree-paypal-tokenize-payment-method", "true"),
        ("woocommerce-add-payment-method-nonce", woo_nonce),
        ("_wp_http_referer", "/my-account/add-payment-method/"),
        ("woocommerce_add_payment_method", "1"),
    ]

    r6 = session.post(f"{SITE_BASE}/my-account/add-payment-method/", headers=h6, data=data6, timeout=REQUEST_TIMEOUT)
    body = r6.text

    if "payment method added" in body.lower() or "payment method added" in body:
        return AddCardOut(
            ok=True, token=token, woo_nonce=woo_nonce,
            auth_fingerprint=auth_fingerprint,
            raw_status_code=r6.status_code,
            message="payment method added successfully",
        )

    # try to extract a decline reason
    m2 = re.search(r"Status code \d+:[^<.\"]+", body) or re.search(r"Reason:\s*([^<.\"]+)", body)
    reason = m2.group(0).strip() if m2 else "unknown decline"
    return AddCardOut(
        ok=False, token=token, woo_nonce=woo_nonce,
        auth_fingerprint=auth_fingerprint,
        raw_status_code=r6.status_code,
        message=f"DECLINED: {reason}",
    )


# ---------------------------------------------------------------- routes

@app.get("/")
def root():
    return {"service": "card-tokenizer", "ok": True}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/add-card", response_model=AddCardOut, dependencies=[Depends(require_api_key)])
def add_card(payload: AddCardIn):
    log.info("add-card request for user=%s card=****%s",
             payload.account.username, payload.card.number[-4:])
    try:
        result = run_flow(
            payload.account,
            payload.card,
            payload.card_type,
            payload.device_data_correlation_id,
        )
    except HTTPException:
        raise
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"upstream request failed: {e}")
    except Exception as e:
        log.exception("flow crashed")
        raise HTTPException(status_code=500, detail=f"internal error: {e}")

    # never echo the full pan back
    log.info("add-card result ok=%s msg=%s", result.ok, result.message)
    return result

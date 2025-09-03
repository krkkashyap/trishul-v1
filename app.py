import os, time, requests
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from dotenv import load_dotenv

try:
    import pyotp
except:
    pyotp = None

load_dotenv()
app = FastAPI(title="Trishul v1 Manual-first", version="1.0.0")

# ===== Config =====
BASE = "https://apiconnect.angelone.in"
ALLOWED = {
    "loginByPassword": ("POST", "/rest/auth/angelbroking/user/v1/loginByPassword"),
    "generateTokens":  ("POST", "/rest/auth/angelbroking/jwt/v1/generateTokens"),
    "getCandleData":   ("POST", "/rest/secure/angelbroking/historical/v1/getCandleData"),
}
API_KEY       = os.getenv("ANGEL_API_KEY", "").strip()
CLIENT_CODE   = os.getenv("ANGEL_CLIENT_CODE", "").strip()
PIN           = os.getenv("ANGEL_PIN", "").strip()
TOTP_SECRET   = os.getenv("ANGEL_TOTP_SECRET", "").strip()
STATE         = os.getenv("ANGEL_STATE", "live").strip()
LOCAL_IP      = os.getenv("CLIENT_LOCAL_IP", "127.0.0.1").strip()
PUBLIC_IP     = os.getenv("CLIENT_PUBLIC_IP", "127.0.0.1").strip()
MAC_ADDR      = os.getenv("CLIENT_MAC", "00:00:00:00:00:00").strip()
TG_TOKEN      = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TG_CHAT_ID    = os.getenv("TELEGRAM_CHAT_ID", "").strip()
CAPITAL       = float(os.getenv("CAPITAL", "200000") or 200000)
RISK_PERCENT  = float(os.getenv("RISK_PERCENT", "1.0") or 1.0)

TOKENS: Dict[str, Optional[str]] = {"jwtToken": None, "refreshToken": None, "feedToken": None}

# ===== Helpers =====
def _build_url(key: str):
    if key not in ALLOWED:
        raise HTTPException(400, f"Unknown endpoint key: {key}")
    method, path = ALLOWED[key]
    return method, BASE + path

def _headers(bearer: Optional[str]=None):
    h = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": LOCAL_IP,
        "X-ClientPublicIP": PUBLIC_IP,
        "X-MACAddress": MAC_ADDR,
        "X-PrivateKey": API_KEY,
    }
    if bearer:
        if not bearer.startswith("Bearer "):
            bearer = f"Bearer {bearer}"
        h["Authorization"] = bearer
    return h

def _safe_call(key: str, body: dict = None, use_auth=True):
    method, url = _build_url(key)
    bearer = TOKENS["jwtToken"] if use_auth else None
    resp = requests.request(method, url, headers=_headers(bearer), json=body or {})
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    data = resp.json()
    if not str(data.get("status")).lower() in ("true", "success"):
        raise HTTPException(400, f"{data.get('errorcode')}: {data.get('message')}")
    return data

def _current_totp():
    if not TOTP_SECRET:
        return None
    if pyotp is None:
        raise HTTPException(500, "pyotp not installed")
    return pyotp.TOTP(TOTP_SECRET).now()

def _login():
    body = {"clientcode": CLIENT_CODE, "password": PIN, "totp": _current_totp() or "", "state": STATE}
    data = _safe_call("loginByPassword", body=body, use_auth=False)
    payload = data.get("data", {})
    TOKENS["jwtToken"]     = payload.get("jwtToken")
    TOKENS["refreshToken"] = payload.get("refreshToken")
    TOKENS["feedToken"]    = payload.get("feedToken")
    return {"status": True, "message": "LOGIN_OK"}

def send_telegram(text: str):
    if not TG_TOKEN or not TG_CHAT_ID:
        return
    try:
        requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                      json={"chat_id": TG_CHAT_ID, "text": text, "parse_mode": "HTML"}, timeout=10)
    except Exception as e:
        print("Telegram send error:", e)

def fetch_candles(exchange: str, symboltoken: str, interval: str = "FIFTEEN_MINUTE", bars: int = 50):
    now = datetime.now()
    from_str = (now - timedelta(minutes=15*bars)).strftime("%Y-%m-%d %H:%M")
    to_str = now.strftime("%Y-%m-%d %H:%M")
    data = _safe_call("getCandleData", body={
        "exchange": exchange,
        "symboltoken": symboltoken,
        "interval": interval,
        "fromdate": from_str,
        "todate": to_str
    })
    return data.get("data", [])

# ===== Routes =====
@app.get("/health")
def health():
    return {
        "env": {"api_key": bool(API_KEY), "client": bool(CLIENT_CODE), "pin": bool(PIN), "totp": bool(TOTP_SECRET),
                "tg": bool(TG_TOKEN and TG_CHAT_ID), "capital": CAPITAL, "risk_percent": RISK_PERCENT},
        "auth": {"jwt": bool(TOKENS["jwtToken"]), "refresh": bool(TOKENS["refreshToken"]), "feed": bool(TOKENS["feedToken"])},
        "ok": True
    }

@app.post("/login")
def login():
    return _login()

@app.get("/signal/notify")
def signal_notify(exchange: str = Query(...), tradingsymbol: str = Query(...), symboltoken: str = Query(...)):
    try:
        candles = fetch_candles(exchange, symboltoken)
        if len(candles) < 10:
            send_telegram(f"⚠️ No-trade: {tradingsymbol} — insufficient candles.")
            return {"status": "NO_TRADE"}
        ltp = candles[-1][4]
        msg = f"📢 SIGNAL for {tradingsymbol}\nLTP: {ltp}\nTime: {datetime.now().strftime('%H:%M:%S')}"
        send_telegram(msg)
        return {"status": "OK", "ltp": ltp}
    except Exception as e:
        send_telegram(f"❌ Signal error for {tradingsymbol}: {str(e)}")
        raise
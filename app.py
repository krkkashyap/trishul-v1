# Trishul v1 (Manual-first): FastAPI + Angel SmartAPI + Telegram alerts
# Strategy: ADX + DI trend filter, RSI(14) pullback (40–45 zone) + ATR-based SL/Targets + Lot sizing

import os, json, time, math, statistics
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List
import requests
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from dotenv import load_dotenv

try:
    import pyotp
except Exception:
    pyotp = None

load_dotenv()
app = FastAPI(title="Trishul v1 Manual-first", version="1.0.0")

# ---------- Config ----------
BASE = "https://apiconnect.angelone.in"
ALLOWED = {
    "loginByPassword": ("POST", "/rest/auth/angelbroking/user/v1/loginByPassword"),
    "generateTokens":  ("POST", "/rest/auth/angelbroking/jwt/v1/generateTokens"),
    "getProfile":      ("GET",  "/rest/secure/angelbroking/user/v1/getProfile"),
    "getRMS":          ("GET",  "/rest/secure/angelbroking/user/v1/getRMS"),
    "getLtpData":      ("POST", "/rest/secure/angelbroking/order/v1/getLtpData"),
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
MASTER_CACHE: Dict[str, Any] = {"ts": 0, "by_symbol": {}}

# ---------- HTTP helpers ----------
def _build_url(key: str) -> Tuple[str,str]:
    if key not in ALLOWED:
        raise HTTPException(400, f"Unknown endpoint key: {key}")
    method, path = ALLOWED[key]
    return method, (BASE + path).strip()

def _headers(bearer: Optional[str]=None) -> Dict[str,str]:
    if not API_KEY:
        raise HTTPException(500, "X-PrivateKey missing (ANGEL_API_KEY)")
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

def _safe_call(key: str, body: Optional[Dict[str,Any]]=None, use_auth=True, timeout=30) -> Dict[str,Any]:
    method, url = _build_url(key)
    bearer = TOKENS["jwtToken"] if use_auth else None
    try:
        resp = requests.request(method, url, headers=_headers(bearer), json=(body or {}) if method=="POST" else None, timeout=timeout)
    except requests.RequestException as e:
        raise HTTPException(502, f"Network error: {e}")
    if resp.status_code in (401,403) and use_auth and TOKENS["refreshToken"]:
        _refresh_tokens()
        resp = requests.request(method, url, headers=_headers(TOKENS["jwtToken"]), json=(body or {}) if method=="POST" else None, timeout=timeout)
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    data = resp.json()
    if isinstance(data, dict) and str(data.get("status")).lower() not in ("true","success"):
        raise HTTPException(400, f"{data.get('errorcode','UNKNOWN')}: {data.get('message','Request failed')}")
    return data

def _current_totp() -> Optional[str]:
    if not TOTP_SECRET:
        return None
    if pyotp is None:
        raise HTTPException(500, "pyotp not installed")
    return pyotp.TOTP(TOTP_SECRET).now()

def _login() -> Dict[str,Any]:
    if not (CLIENT_CODE and PIN):
        raise HTTPException(400, "CLIENT_CODE/PIN missing")
    body = {"clientcode": CLIENT_CODE, "password": PIN, "totp": _current_totp() or "", "state": STATE}
    data = _safe_call("loginByPassword", body=body, use_auth=False)
    payload = data.get("data", {}) or {}
    TOKENS["jwtToken"]     = payload.get("jwtToken")
    TOKENS["refreshToken"] = payload.get("refreshToken")
    TOKENS["feedToken"]    = payload.get("feedToken")
    if not TOKENS["jwtToken"]:
        raise HTTPException(500, "Login failed: jwtToken missing")
    return {"status": True, "message": "LOGIN_OK"}

def _refresh_tokens() -> Dict[str,Any]:
    if not TOKENS["refreshToken"]:
        raise HTTPException(401, "No refreshToken available")
    body = {"refreshToken": TOKENS["refreshToken"]}
    data = _safe_call("generateTokens", body=body, use_auth=True)
    payload = data.get("data", {}) or {}
    TOKENS["jwtToken"]     = payload.get("jwtToken") or TOKENS["jwtToken"]
    TOKENS["refreshToken"] = payload.get("refreshToken") or TOKENS["refreshToken"]
    TOKENS["feedToken"]    = payload.get("feedToken") or TOKENS["feedToken"]
    if not TOKENS["jwtToken"]:
        raise HTTPException(500, "Token refresh failed")
    return {"status": True, "message": "REFRESH_OK"}

# ---------- Telegram ----------
def send_telegram(text: str) -> None:
    if not TG_TOKEN or not TG_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    try:
        requests.post(url, json={"chat_id": TG_CHAT_ID, "text": text, "parse_mode": "HTML"}, timeout=20)
    except Exception as e:
        print("Telegram send error:", e)

# ---------- Candle fetch ----------
def fetch_candles(exchange: str, symboltoken: str, interval: str, bars: int = 300) -> List[List[Any]]:
    minutes = {"ONE_MINUTE": 1, "THREE_MINUTE": 3, "FIVE_MINUTE": 5, "TEN_MINUTE": 10,
               "FIFTEEN_MINUTE": 15, "THIRTY_MINUTE": 30, "ONE_HOUR": 60, "ONE_DAY": 1440}.get(interval, 5)
    span_min = max(minutes * (bars + 5), minutes*50)
    now = datetime.now()
    to_str = now.strftime("%Y-%m-%d %H:%M")
    from_str = (now - timedelta(minutes=span_min)).strftime("%Y-%m-%d %H:%M")
    data = _safe_call("getCandleData", body={
        "exchange": exchange,
        "symboltoken": symboltoken,
        "interval": interval,
        "fromdate": from_str,
        "todate": to_str
    })
    return data
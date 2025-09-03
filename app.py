# app.py
# Trishul v1 (Manual-first): FastAPI + Angel SmartAPI + Telegram alerts
# Strategy: ADX + DI trend filter, RSI(14) pullback (40–45 zone) + ATR-based SL/Targets + Lot sizing
# Zero-cost deploy friendly (Railway). No auto-orders; pre-trade notifications only.

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
RISK_PERCENT  = float(os.getenv("RISK_PERCENT", "1.0") or 1.0)  # percent per trade

TOKENS: Dict[str, Optional[str]] = {"jwtToken": None, "refreshToken": None, "feedToken": None}
MASTER_CACHE: Dict[str, Any] = {"ts": 0, "by_symbol": {}}

# ---------- HTTP helpers ----------
def _build_url(key: str) -> Tuple[str,str]:
    if key not in ALLOWED:
        raise HTTPException(400, f"Unknown endpoint key: {key}")
    method, path = ALLOWED[key]
    url = (BASE + path).strip()
    if ("\n" in url) or ("\r" in url) or ("  " in url):
        raise HTTPException(400, f"Malformed URL: {repr(url)}")
    return method, url

def _headers(bearer: Optional[str]=None) -> Dict[str,str]:
    if not API_KEY:
        raise HTTPException(500, "X-PrivateKey missing (ANGEL_API_KEY)")
    h = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": LOCAL_IP or "127.0.0.1",
        "X-ClientPublicIP": PUBLIC_IP or "127.0.0.1",
        "X-MACAddress": MAC_ADDR or "00:00:00:00:00:00",
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
    try:
        data = resp.json()
    except ValueError:
        raise HTTPException(500, "Non-JSON response")
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
        raise HTTPException(400, "Telegram BOT_TOKEN/CHAT_ID missing")
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    resp = requests.post(url, json={"chat_id": TG_CHAT_ID, "text": text, "parse_mode": "HTML"}, timeout=20)
    if resp.status_code != 200:
        raise HTTPException(502, f"Telegram error: {resp.text}")

# ---------- Candle fetch ----------
def fetch_candles(exchange: str, symboltoken: str, interval: str, bars: int = 300) -> List[List[Any]]:
    # Make sure we fetch enough minutes for 'bars'
    minutes = {
        "ONE_MINUTE": 1, "THREE_MINUTE": 3, "FIVE_MINUTE": 5, "TEN_MINUTE": 10,
        "FIFTEEN_MINUTE": 15, "THIRTY_MINUTE": 30, "ONE_HOUR": 60, "ONE_DAY": 24*60
    }.get(interval, 5)
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
    return data.get("data", [])

# ---------- Indicators ----------
def rsi(closes: List[float], period: int = 14) -> List[float]:
    if len(closes) < period + 1:
        return []
    gains, losses = [], []
    for i in range(1, len(closes)):
        change = closes[i] - closes[i-1]
        gains.append(max(change, 0.0))
        losses.append(max(-change, 0.0))
    avg_gain = sum(gains[:period]) / period
    avg_loss = sum(losses[:period]) / period
    rsis = [None]*(period)  # first 'period' are None
    for i in range(period, len(gains)):
        avg_gain = (avg_gain*(period-1) + gains[i]) / period
        avg_loss = (avg_loss*(period-1) + losses[i]) / period
        if avg_loss == 0:
            rs = float('inf')
        else:
            rs = avg_gain / avg_loss
        r = 100 - (100/(1+rs))
        rsis.append(r)
    return rsis

def adx_di(highs: List[float], lows: List[float], closes: List[float], period: int = 14) -> Dict[str, float]:
    n = len(closes)
    if n < period + 2:
        return {"adx": 0.0, "plus_di": 0.0, "minus_di": 0.0}
    tr_list, plus_dm_list, minus_dm_list = [], [], []
    for i in range(1, n):
        tr = max(highs[i]-lows[i], abs(highs[i]-closes[i-1]), abs(lows[i]-closes[i-1]))
        up_move = highs[i] - highs[i-1]
        down_move = lows[i-1] - lows[i]
        plus_dm = up_move if (up_move > down_move and up_move > 0) else 0.0
        minus_dm = down_move if (down_move > up_move and down_move > 0) else 0.0
        tr_list.append(tr); plus_dm_list.append(plus_dm); minus_dm_list.append(minus_dm)
    # Wilder smoothing
    tr14 = sum(tr_list[:period])
    plus14 = sum(plus_dm_list[:period])
    minus14 = sum(minus_dm_list[:period])
    tr_s, plus_s, minus_s = [tr14], [plus14], [minus14]
    for i in range(period, len(tr_list)):
        tr_s.append(tr_s[-1] - (tr_s[-1]/period) + tr_list[i])
        plus_s.append(plus_s[-1] - (plus_s[-1]/period) + plus_dm_list[i])
        minus_s.append(minus_s[-1] - (minus_s[-1]/period) + minus_dm_list[i])
    if not tr_s:
        return {"adx": 0.0, "plus_di": 0.0, "minus_di": 0.0}
    last_tr = tr_s[-1] or 1e-9
    plus_di = 100 * (plus_s[-1] / last_tr)
    minus_di = 100 * (minus_s[-1] / last_tr)
    dx_vals = []
    for i in range(len(plus_s)):
        trv = tr_s[i] or 1e-9
        pdi = 100 * (plus_s[i] / trv)
        mdi = 100 * (minus_s[i] / trv)
        dx = 100 * abs(pdi - mdi) / max(pdi + mdi, 1e-9)
        dx_vals.append(dx)
    # ADX smoothing
    if len(dx_vals) < period:
        adx = dx_vals[-1]
    else:
        adx = sum(dx_vals[:period]) / period
        for i in range(period, len(dx_vals)):
            adx = (adx*(period-1) + dx_vals[i]) / period
    return {"adx": adx, "plus_di": plus_di, "minus_di": minus_di}

def atr_from_candles(candles: List[List[Any]], period: int=14) -> float:
    if len(candles) < period + 1:
        return 0.0
    trs = []
    prev_close = candles[0][4]
    for i in range(1, len(candles)):
        h, l = candles[i][2], candles[i][3]
        tr = max(h-l, abs(h-prev_close), abs(l-prev_close))
        trs.append(tr)
        prev_close = candles[i][4]
    if len(trs) < period:
        return 0.0
    # Wilder's ATR
    atr = sum(trs[:period]) / period
    for i in range(period, len(trs)):
        atr = (atr*(period-1) + trs[i]) / period
    return atr

# ---------- Lot size (from instrument master, cached) ----------
def get_lot_multiplier(tradingsymbol: str) -> Optional[int]:
    # Cached master refresh every 6 hours
    now = time.time()
    if now - MASTER_CACHE["ts"] > 6*3600 or not MASTER_CACHE["by_symbol"]:
        try:
            url = "https://margincalculator.angelbroking.com/OpenAPI_File/files/OpenAPIScripMaster.json"
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            data = r.json()
            by_sym = {}
            for row in data:
                tsym = row.get("symbol") or row.get("tradingsymbol")
                lot = row.get("lotsize") or row.get("lot_size")
                if tsym and lot:
                    by_sym[str(tsym).upper()] = int(float(lot))
            MASTER_CACHE["by_symbol"] = by_sym
            MASTER_CACHE["ts"] = now
        except Exception:
            return None
    return MASTER_CACHE["by_symbol"].get(tradingsymbol.upper())

def compute_lot_size(atr_points: float, lot_multiplier: int) -> int:
    if atr_points <= 0 or lot_multiplier <= 0:
        return 0
    risk_rupees = CAPITAL * (RISK_PERCENT/100.0)
    denom = atr_points * lot_multiplier
    lots = int(risk_rupees // max(denom, 1e-6))
    return max(lots, 0)

# ---------- Strategy: ADX + RSI pullback + ATR SL/Targets ----------
def generate_signal(exchange: str, tradingsymbol: str, symboltoken: str) -> Dict[str,Any]:
    candles = fetch_candles(exchange, symboltoken, "FIFTEEN_MINUTE", bars=220)
    if not candles or len(candles) < 60:
        raise HTTPException(400, "Insufficient candles")
    # each candle: [ts, open, high, low, close, vol]
    highs = [row[2] for row in candles]
    lows  = [row[3] for row in candles]
    closes= [row[4] for row in candles]
    ltp = closes[-1]

    # Indicators
    adxres = adx_di(highs, lows, closes, period=14)
    adx_v, plus_di, minus_di = adxres["adx"], adxres["plus_di"], adxres["minus_di"]
    rsi_arr = rsi(closes, period=14)
    rsi_last = rsi_arr[-1] if rsi_arr and rsi_arr[-1] is not None else None
    rsi_prev = rsi_arr[-2] if rsi_arr and rsi_arr[-2] is not None else None
    atr_val = atr_from_candles(candles, period=14)

    # Regime and entry
    adx_min = 20.0
    rsi_low_thr = 45.0   # pullback zone lower edge
    rsi_entry_thr = 50.0 # regain strength

    regime_ok = (adx_v >= adx_min) and (plus_di > minus_di)
    rsi_pullback_bounce = (rsi_prev is not None and rsi_last is not None and rsi_prev <= rsi_low_thr and rsi_last > rsi_entry_thr)

    direction = "BUY" if (regime_ok and rsi_pullback_bounce) else "NONE"

    # Targets and SL
    atr = max(atr_val, 0.05)
    time_stop_bars = 5
    if direction == "BUY":
        entry  = ltp
        sl     = round(ltp - 1.2*atr, 2)
        tp1    = round(ltp + 1.0*atr, 2)
        tp2    = round(ltp + 1.8*atr, 2)
        tp3    = round(ltp + 3.0*atr, 2)
    else:
        entry=sl=tp1=tp2=tp3=None

    # Confidence (blend of ADX strength + pullback quality)
    if direction == "BUY":
        adx_score = max(0, min(100, (adx_v-20)*3))   # ADX 20→~50 => 0→90
        pullback_depth = max(0.0, (50.0 - min(max(rsi_prev or 50.0, 0), 50.0))) # deeper pullback (<=45) better
        pb_score = max(0, min(100, 50 + pullback_depth))
        confidence = int(0.6*adx_score + 0.4*pb_score)
    else:
        confidence = 30

    # Lot sizing
    lot_mult = get_lot_multiplier(tradingsymbol) or 1
    lots = compute_lot_size(atr, lot_mult)

    return {
        "symbol": tradingsymbol,
        "exchange": exchange,
        "ltp": round(ltp,2),
        "direction": direction,
        "confidence": confidence,
        "indicators": {
            "adx": round(adx_v,2), "plus_di": round(plus_di,2), "minus_di": round(minus_di,2),
            "rsi_prev": round(rsi_prev,2) if rsi_prev is not None else None,
            "rsi_last": round(rsi_last,2) if rsi_last is not None else None,
            "atr": round(atr,2)
        },
        "plan": {
            "entry": entry, "sl": sl, "targets": [tp1, tp2, tp3],
            "time_stop_bars": time_stop_bars,
            "trail": "ATR-based manual trail recommended (e.g., 1.0×ATR)"
        },
        "risk": {
            "capital": CAPITAL, "risk_percent": RISK_PERCENT,
            "lot_multiplier": lot_mult, "suggested_lots": lots
        },
        "valid_for_min": 5,
        "notes": "Manual-first alert. Review before execution."
    }

# ---------- Models ----------
class LtpReq(BaseModel):
    exchange: str
    tradingsymbol: str
    symboltoken: str

# ---------- Routes ----------
@app.get("/health")
def health():
    return {
        "env": {"api_key": bool(API_KEY), "client": bool(CLIENT_CODE), "pin": bool(PIN), "totp": bool(TOTP_SECRET),
                "tg": bool(TG_TOKEN and TG_CHAT_ID), "capital": CAPITAL, "risk_percent": RISK_PERCENT},
        "auth": {"jwt": bool(TOKENS["jwtToken"]), "refresh": bool(TOKENS["refreshToken"]), "feed": bool(TOKENS["feedToken"])},
        "ok": True
    }

@app.post("/login")
def login(): return _login()

@app.get("/profile")
def profile():
    data = _safe_call("getProfile"); return data.get("data", data)

@app.post("/ltp")
def ltp(req: LtpReq):
    data = _safe_call("getLtpData", body=req.dict()); return data.get("data", data)

@app.get("/signal/preview")
def signal_preview(exchange: str = Query(...), tradingsymbol: str = Query(...), symboltoken: str = Query(...)):
    return generate_signal(exchange, tradingsymbol, symboltoken)

@app.get("/signal/notify")
def signal_notify(exchange: str = Query(...), tradingsymbol: str = Query(...), symboltoken: str = Query(...)):
    sig = generate_signal(exchange, tradingsymbol, symboltoken)
    if sig["direction"] == "NONE":
        send_telegram(
            f"⚠️ No-trade: <b>{sig['symbol']}</b>\n"
            f"LTP: {sig['ltp']} | ADX: {sig['indicators']['adx']}\n"
            f"RSI(prev→last): {sig['indicators']['rsi_prev']} → {sig['indicators']['rsi_last']}"
        )
        return {"notified": "no-trade", "signal": sig}
    tgs = ", ".join(str(x) for x in sig["plan"]["targets"])
    msg = (
        f"🛡️ Trishul v1 (Manual)\n"
        f"Symbol: <b>{sig['symbol']}</b> | Exch: {sig['exchange']}\n"
        f"Direction: <b>{sig['direction']}</b> | Confidence: <b>{sig['confidence']}%</b>\n"
        f"LTP: {sig['ltp']} | ADX: {sig['indicators']['adx']} | RSI: {sig['indicators']['rsi_last']}\n"
        f"Entry: <b>{sig['plan']['entry']}</b> | SL: <b>{sig['plan']['sl']}</b>\n"
        f"Targets: <b>{tgs}</b>\n"
        f"Lots: <b>{sig['risk']['suggested_lots']}</b> (Lot x {sig['risk']['lot_multiplier']}) | Risk%: {sig['risk']['risk_percent']}\n"
        f"Validity: {sig['valid_for_min']}m | Trail: {sig['plan']['trail']}"
    )
    send_telegram(msg)
    return {"notified": True, "signal": sig}

@app.on_event("startup")
def _startup_try_login():
    try:
        if CLIENT_CODE and PIN:
            _login()
    except Exception:
        pass
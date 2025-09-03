\# Trishul v1 Manual-first

FastAPI service for manual-first, pre-trade alerts (ADX + RSI Pullback + ATR + Lot sizing).



Endpoints:

\- GET /health

\- POST /login

\- GET /profile

\- GET /signal/preview?exchange=NSE\&tradingsymbol=SBIN-EQ\&symboltoken=3045

\- GET /signal/notify?exchange=NSE\&tradingsymbol=SBIN-EQ\&symboltoken=3045



Deploy: Railway (free-tier). Set env vars from .env.example.


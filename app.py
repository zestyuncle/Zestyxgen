# app.py — Zesty Guest Register API (scripts only)
import os, json, hmac, hashlib, random, string, time, logging
from flask import Flask, request, jsonify
import requests

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("zesty")

app = Flask(__name__)

# ══════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════
OAUTH_BASE = "https://ffmconnect.ppmainecoonghj.com"
SECRET     = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
APP_ID     = 100067
SALT       = "BY_ZESTY"
TIMEOUT    = 12

WEBHOOK_URL       = os.environ.get("WEBHOOK_URL", "")
KV_REST_API_URL   = os.environ.get("KV_REST_API_URL", "")
KV_REST_API_TOKEN = os.environ.get("KV_REST_API_TOKEN", "")

MSDK = [
    "GarenaMSDK/4.0.42(KB2003 ;Android 13;en;HK;app 2.130.1 2019118332;)",
    "GarenaMSDK/4.0.42(SM-G998B ;Android 14;en;IN;app 2.131.0 2019118527;)",
    "GarenaMSDK/4.0.42(CPH2095 ;Android 12;en;ID;app 2.129.1 2019118142;)",
    "GarenaMSDK/4.0.42(Pixel 6 ;Android 14;en;US;app 2.131.1 2019118602;)",
]

# ══════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════
def sign(payload):
    b = json.dumps(payload, separators=(",", ":"))
    return hmac.new(SECRET.encode(), b.encode(), hashlib.sha256).hexdigest()

def gen_password(prefix, mode):
    if mode == "custom":
        return prefix or "ZESTY"
    if mode == "base":
        cs = string.ascii_uppercase + string.digits
        p1 = "".join(random.choices(cs, k=5))
        p2 = "".join(random.choices(cs, k=5))
        return f"{prefix or 'Zesty'}_{p1}_{SALT}_{p2}"
    return "".join(random.choices(string.ascii_uppercase, k=64))

def read_params():
    j = request.get_json(force=True, silent=True)
    if isinstance(j, dict): return j
    if request.form: return request.form.to_dict()
    return request.args.to_dict()

def save_account(account):
    log.info(f"[CREATED] uid={account['uid']} pwd={account['password'][:12]}… region={account['region']}")
    if WEBHOOK_URL:
        try: requests.post(WEBHOOK_URL, json=account, timeout=4)
        except Exception as e: log.warning(f"webhook fail: {e}")
    if KV_REST_API_URL and KV_REST_API_TOKEN:
        try:
            requests.post(f"{KV_REST_API_URL}/set/zesty:account:{account['uid']}",
                headers={"Authorization": f"Bearer {KV_REST_API_TOKEN}"},
                data=json.dumps(account), timeout=4)
        except Exception as e: log.warning(f"kv fail: {e}")

def do_register(params):
    mode     = str(params.get("mode", "custom") or "custom").lower()
    password = str(params.get("password", "ZESTY") or "ZESTY")
    region   = str(params.get("region", "") or "")

    if mode not in ("custom", "base", "random"):
        return {"ok": False, "error": f"invalid mode '{mode}' (custom|base|random)"}

    pwd = gen_password(password, mode)
    payload = {"app_id": APP_ID, "client_type": 2, "password": pwd, "source": 2}
    headers = {
        "User-Agent": random.choice(MSDK),
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Signature {sign(payload)}",
    }

    start = time.time()
    try:
        r = requests.post(
            f"{OAUTH_BASE}/api/v2/oauth/guest:register",
            data=json.dumps(payload, separators=(",", ":")),
            headers=headers, timeout=TIMEOUT,
        )
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "timeout contacting Garena"}
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": f"network: {e}"}

    elapsed = round(time.time() - start, 2)

    try:
        d = r.json()
    except Exception:
        return {"ok": False, "http_status": r.status_code,
                "error": "non-json response", "raw": r.text[:300],
                "elapsed_s": elapsed}

    if r.status_code != 200 or d.get("code") != 0:
        log.warning(f"[FAIL] http={r.status_code} code={d.get('code')} msg={d.get('message','')}")
        return {"ok": False, "http_status": r.status_code,
                "code": d.get("code"), "message": d.get("message", ""),
                "raw": d, "password": pwd, "region": region,
                "elapsed_s": elapsed}

    uid = (d.get("data") or {}).get("uid")
    if not uid:
        return {"ok": False, "error": "no uid in response",
                "raw": d, "password": pwd, "elapsed_s": elapsed}

    account = {"ok": True, "uid": str(uid), "password": pwd,
               "region": region, "mode": mode, "elapsed_s": elapsed}
    save_account(account)
    return account

# ══════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "zesty-guest-register",
        "status": "ok",
        "endpoints": {
            "POST /api/register": '{"password":"ZESTY","mode":"custom"}',
            "GET  /api/register": "?password=ZESTY&mode=custom",
            "GET  /api/health":   "health check",
        },
        "modes": {
            "custom": "use password exactly as given",
            "base":   "prefix_XXXXX_BY_ZESTY_XXXXX",
            "random": "64 random uppercase letters",
        },
    })

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "ts": int(time.time()), "service": "zesty-register"})

@app.route("/api/register", methods=["GET", "POST", "OPTIONS"])
def api_register():
    if request.method == "OPTIONS":
        return ("", 204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        })
    try:
        result = do_register(read_params())
        status = 200 if result.get("ok") else (
            400 if result.get("code") or result.get("error", "").startswith("invalid") else 502
        )
        resp = jsonify(result)
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, status
    except Exception as e:
        log.exception("register crash")
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500

@app.errorhandler(404)
def nf(e):
    return jsonify({"ok": False, "error": "not found",
                    "try": "/api/register"}), 404

@app.errorhandler(405)
def mna(e):
    return jsonify({"ok": False, "error": "method not allowed",
                    "hint": "GET or POST on /api/register"}), 405

handler = app

"""
FakeShield API v3.0
──────────────────────────────────────────────────────────────────
Backend: Flask + AWS DynamoDB + AWS SNS + HuggingFace AI + JWT Auth
──────────────────────────────────────────────────────────────────
Required .env variables:
  AWS_ACCESS_KEY_ID=
  AWS_SECRET_ACCESS_KEY=
  AWS_REGION=ap-south-1
  DYNAMODB_REPORTS_TABLE=fakeshield_reports
  DYNAMODB_USERS_TABLE=fakeshield_users
  SNS_TOPIC_ARN=arn:aws:sns:ap-south-1:XXXX:FakeShieldAlerts
  HF_API_TOKEN=hf_xxxxxxxxxxxxxxxxxxxx
  JWT_SECRET=your_super_secret_key_change_this
  PORT=5000
──────────────────────────────────────────────────────────────────
"""

import os, re, uuid, hashlib, hmac, json, time, base64, requests
from datetime import datetime, timezone
from functools import wraps

import boto3
from boto3.dynamodb.conditions import Key
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)

# ════════════════════════════════════════════════════════════════
#  CONFIG
# ════════════════════════════════════════════════════════════════
AWS_REGION     = os.getenv("AWS_REGION", "ap-south-1")
REPORTS_TABLE  = os.getenv("DYNAMODB_REPORTS_TABLE", "fakeshield_reports")
USERS_TABLE    = os.getenv("DYNAMODB_USERS_TABLE",   "fakeshield_users")
SNS_TOPIC_ARN  = os.getenv("SNS_TOPIC_ARN", "")
HF_API_TOKEN   = os.getenv("HF_API_TOKEN", "")
JWT_SECRET     = os.getenv("JWT_SECRET", "changeme_secret")
HF_BASE        = "https://api-inference.huggingface.co/models"
SPAM_MODEL     = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
ZEROSHOT_MODEL = "facebook/bart-large-mnli"


# ════════════════════════════════════════════════════════════════
#  AWS CLIENTS
#  On EC2 with IAM Role attached: boto3 picks credentials
#  automatically — leave AWS_ACCESS_KEY_ID blank in that case.
# ════════════════════════════════════════════════════════════════
def _aws_kw():
    kw = {"region_name": AWS_REGION}
    key, secret = os.getenv("AWS_ACCESS_KEY_ID"), os.getenv("AWS_SECRET_ACCESS_KEY")
    if key and secret:
        kw.update(aws_access_key_id=key, aws_secret_access_key=secret)
    token = os.getenv("AWS_SESSION_TOKEN")
    if token:
        kw["aws_session_token"] = token
    return kw


dynamodb       = boto3.resource("dynamodb", **_aws_kw())
sns_client     = boto3.client("sns",        **_aws_kw())
reports_table  = dynamodb.Table(REPORTS_TABLE)
users_table    = dynamodb.Table(USERS_TABLE)


# ════════════════════════════════════════════════════════════════
#  DYNAMODB TABLE BOOTSTRAP (idempotent)
# ════════════════════════════════════════════════════════════════
def _create_table_if_missing(name, key_schema, attr_defs, gsi=None):
    client = boto3.client("dynamodb", **_aws_kw())
    try:
        existing = client.list_tables()["TableNames"]
    except Exception as e:
        print(f"  ✗ Cannot list DynamoDB tables: {e}")
        return
    if name in existing:
        print(f"  ✓ Table exists: {name}")
        return
    kw = dict(TableName=name, KeySchema=key_schema,
              AttributeDefinitions=attr_defs, BillingMode="PAY_PER_REQUEST")
    if gsi:
        kw["GlobalSecondaryIndexes"] = gsi
    client.create_table(**kw)
    client.get_waiter("table_exists").wait(TableName=name)
    print(f"  ✓ Created table: {name}")


def init_dynamo():
    print("Initialising DynamoDB …")
    # ── Reports: PK=identifier  SK=report_id ────────────────────
    _create_table_if_missing(
        REPORTS_TABLE,
        key_schema=[{"AttributeName": "identifier", "KeyType": "HASH"},
                    {"AttributeName": "report_id",  "KeyType": "RANGE"}],
        attr_defs=[{"AttributeName": "identifier", "AttributeType": "S"},
                   {"AttributeName": "report_id",  "AttributeType": "S"}],
    )
    # ── Users: PK=email ─────────────────────────────────────────
    _create_table_if_missing(
        USERS_TABLE,
        key_schema=[{"AttributeName": "email", "KeyType": "HASH"}],
        attr_defs=[{"AttributeName": "email", "AttributeType": "S"}],
    )


# ════════════════════════════════════════════════════════════════
#  PURE-STDLIB JWT  (HS256 — no extra package)
# ════════════════════════════════════════════════════════════════
def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4) % 4)

def jwt_encode(payload: dict, expires_in=86400) -> str:
    payload = {**payload, "exp": int(time.time()) + expires_in, "iat": int(time.time())}
    hdr  = _b64u(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    body = _b64u(json.dumps(payload).encode())
    sig  = _b64u(hmac.new(JWT_SECRET.encode(), f"{hdr}.{body}".encode(), hashlib.sha256).digest())
    return f"{hdr}.{body}.{sig}"

def jwt_decode(token: str) -> dict:
    try:
        h, b, s = token.split(".")
        expected = _b64u(hmac.new(JWT_SECRET.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(s, expected):
            raise ValueError("Bad signature")
        payload = json.loads(_b64d(b))
        if payload.get("exp", 0) < time.time():
            raise ValueError("Token expired")
        return payload
    except Exception as e:
        raise ValueError(str(e))

def require_auth(f):
    @wraps(f)
    def dec(*a, **kw):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorised — token missing"}), 401
        try:
            g.user = jwt_decode(auth[7:])
        except ValueError as e:
            return jsonify({"error": str(e)}), 401
        return f(*a, **kw)
    return dec

def optional_auth(f):
    @wraps(f)
    def dec(*a, **kw):
        g.user = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            try: g.user = jwt_decode(auth[7:])
            except ValueError: pass
        return f(*a, **kw)
    return dec


# ════════════════════════════════════════════════════════════════
#  PASSWORD HELPERS
# ════════════════════════════════════════════════════════════════
def hash_pw(pw: str) -> str:
    salt = os.urandom(16).hex()
    h    = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260_000).hex()
    return f"{salt}${h}"

def verify_pw(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$")
        return hmac.compare_digest(
            hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 260_000).hex(), h)
    except Exception:
        return False


# ════════════════════════════════════════════════════════════════
#  SNS
# ════════════════════════════════════════════════════════════════
def sns_notify(subject: str, body: str):
    if not SNS_TOPIC_ARN:
        return
    try:
        sns_client.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=body)
    except Exception as e:
        print(f"[SNS] {e}")


# ════════════════════════════════════════════════════════════════
#  HUGGING FACE
# ════════════════════════════════════════════════════════════════
def _hf_hdr():
    h = {"Content-Type": "application/json"}
    if HF_API_TOKEN:
        h["Authorization"] = f"Bearer {HF_API_TOKEN}"
    return h

def detect_id_type(v: str) -> str:
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v): return "email"
    if re.match(r"^\+?[\d\s\-().]{7,20}$", v):       return "phone"
    return "unknown"

def hf_spam(text: str) -> dict:
    try:
        r = requests.post(
            f"{HF_BASE}/{SPAM_MODEL}",
            headers=_hf_hdr(),
            json={"inputs": text, "options": {"wait_for_model": True}},
            timeout=15
        )

        r.raise_for_status()
        data = r.json()

        # Handle nested list response
        if isinstance(data, list):
            if len(data) > 0 and isinstance(data[0], list):
                data = data[0]

        if isinstance(data, list) and len(data) > 0:
            return max(data, key=lambda x: x.get("score", 0))

    except Exception as e:
        print("[HF spam ERROR]", e)

    return {"label": "UNKNOWN", "score": 0.0}

def hf_zero_shot(text: str, labels: list) -> dict:
    try:
        r = requests.post(f"{HF_BASE}/{ZEROSHOT_MODEL}", headers=_hf_hdr(),
                          json={"inputs": text, "parameters": {"candidate_labels": labels},
                                "options": {"wait_for_model": True}}, timeout=20)
        r.raise_for_status()
        d = r.json()
        if "labels" in d: return dict(zip(d["labels"], d["scores"]))
    except Exception as e:
        print(f"[HF zshot] {e}")
    return {}

def build_ai_analysis(identifier: str, stats: dict) -> dict:
    scam, spam, genuine = stats.get("scamCount",0), stats.get("spamCount",0), stats.get("genuineCount",0)
    total, risk = stats.get("totalReports",0), stats.get("riskScore",0)
    id_type = detect_id_type(identifier)
    ctx = f"This {id_type} {identifier} was reported {scam}× scam, {spam}× spam, {genuine}× genuine out of {total} reports."
    sr = hf_spam(
    f"Message from {identifier}. Could this be phishing or spam?"
    )
    lbl, sc = sr.get("label","UNKNOWN").upper(), sr.get("score",0.0)
    zs  = hf_zero_shot(ctx, ["phishing scam","financial fraud","spam marketing",
                              "legitimate business","identity theft","harmless contact"])
    flags = []
    if lbl == "SPAM":  flags.append({"label":"AI: Spam Pattern","level":"warning"})
    elif lbl == "HAM" and risk < 20: flags.append({"label":"AI: Looks Legitimate","level":"safe"})
    for l, s in sorted(zs.items(), key=lambda x:-x[1])[:3]:
        if s > 0.2:
            lvl = "safe" if ("legitimate" in l or "harmless" in l) else ("danger" if s>0.4 else "warning")
            flags.append({"label":f"{l.title()} ({s:.0%})","level":lvl})
    if scam:    flags.append({"label":f"{scam} Scam Report(s)","level":"danger"})
    if spam:    flags.append({"label":f"{spam} Spam Report(s)","level":"warning"})
    if genuine: flags.append({"label":f"{genuine} Genuine Report(s)","level":"safe"})
    top = max(zs.items(), key=lambda x:x[1], default=("unknown",0)) if zs else ("unknown",0)
    tone = "HIGH RISK" if risk>=70 else ("MEDIUM RISK" if risk>=30 else "LOW RISK")
    hf_note = f"HF: {lbl} ({sc:.0%})." if lbl!="UNKNOWN" else "HF model unavailable."
    return {"verdict":tone,
            "summary":f"{tone}. {hf_note} Top: {top[0].title()} ({top[1]:.0%}). Reports: {total}.",
            "flags":flags[:6], "hfLabel":lbl, "hfConfidence":round(sc,4),
            "topCategory":top[0], "identifierType":id_type}


# ════════════════════════════════════════════════════════════════
#  DYNAMODB CRUD
# ════════════════════════════════════════════════════════════════
def _risk(sc, sp, ge, tot):
    if not tot: return 0
    return round(max(0, min(100, ((sc*50)+(sp*30)+(ge*-20))/tot)), 2)

def db_create_report(identifier, rtype, message, user_email=None):
    rid = str(uuid.uuid4())
    ts  = datetime.now(timezone.utc).isoformat()
    item = {"identifier": identifier, "report_id": rid, "type": rtype,
            "message": message, "created_at": ts,
            "reported_by": user_email or "anonymous"}
    reports_table.put_item(Item=item)
    if rtype == "Scam":
        sns_notify(f"[FakeShield] SCAM reported: {identifier}",
                   f"Identifier : {identifier}\nReporter   : {user_email or 'anon'}\nTime       : {ts}\nDetails    : {message}")
    return {**item, "tagType": rtype, "createdAt": ts}

def db_stats(identifier):
    items = reports_table.query(
        KeyConditionExpression=Key("identifier").eq(identifier)).get("Items", [])
    sc = sum(1 for r in items if r.get("type","").lower()=="scam")
    sp = sum(1 for r in items if r.get("type","").lower()=="spam")
    ge = sum(1 for r in items if r.get("type","").lower()=="genuine")
    tot = len(items)
    risk = _risk(sc, sp, ge, tot)
    reports = sorted([{"id":r.get("report_id"),"identifier":r.get("identifier"),
                       "tagType":r.get("type"),"message":r.get("message"),
                       "createdAt":r.get("created_at"),"reportedBy":r.get("reported_by")} for r in items],
                     key=lambda x:x.get("createdAt",""), reverse=True)
    return {"identifier":identifier,"totalReports":tot,"scamCount":sc,"spamCount":sp,
            "genuineCount":ge,"riskScore":risk,"scamScore":risk,
            "tags":list(set(r.get("type","") for r in items)),"reports":reports}

def db_all_reports(limit=100):
    resp  = reports_table.scan(Limit=min(limit, 1000))
    items = resp.get("Items", [])
    return sorted([{"id":r.get("report_id"),"identifier":r.get("identifier"),
                    "tagType":r.get("type"),"message":r.get("message"),
                    "createdAt":r.get("created_at"),"reportedBy":r.get("reported_by")} for r in items],
                  key=lambda x:x.get("createdAt",""), reverse=True)[:limit]

def db_dashboard():
    items   = reports_table.scan(ProjectionExpression="#t",
                                  ExpressionAttributeNames={"#t":"type"}).get("Items",[])
    total   = len(items)
    sc = sum(1 for r in items if r.get("type")=="Scam")
    sp = sum(1 for r in items if r.get("type")=="Spam")
    ge = sum(1 for r in items if r.get("type")=="Genuine")
    ids = len(set(r.get("identifier","") for r in
                  reports_table.scan(ProjectionExpression="identifier").get("Items",[])))
    return {"totalReports":total,"scamCount":sc,"spamCount":sp,"genuineCount":ge,"uniqueIdentifiers":ids}


# ════════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ════════════════════════════════════════════════════════════════
@app.route("/api/auth/register", methods=["POST"])
def register():
    d = request.get_json() or {}
    email    = d.get("email","").strip().lower()
    password = d.get("password","")
    name     = d.get("name","").strip()
    if not email or not password:
        return jsonify({"error":"Email and password required"}), 400
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error":"Invalid email"}), 400
    if len(password) < 6:
        return jsonify({"error":"Password must be ≥ 6 characters"}), 400
    if users_table.get_item(Key={"email":email}).get("Item"):
        return jsonify({"error":"Email already registered"}), 409
    ts   = datetime.now(timezone.utc).isoformat()
    uname = name or email.split("@")[0]
    users_table.put_item(Item={"email":email,"name":uname,
                               "password":hash_pw(password),"created_at":ts,"role":"user"})
    sns_notify("[FakeShield] New user", f"Email: {email}\nTime: {ts}")
    token = jwt_encode({"email":email,"name":uname,"role":"user"})
    return jsonify({"success":True,"token":token,"user":{"email":email,"name":uname,"role":"user"}}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    d     = request.get_json() or {}
    email = d.get("email","").strip().lower()
    pw    = d.get("password","")
    if not email or not pw:
        return jsonify({"error":"Email and password required"}), 400
    item = users_table.get_item(Key={"email":email}).get("Item")
    if not item or not verify_pw(pw, item.get("password","")):
        return jsonify({"error":"Invalid email or password"}), 401
    token = jwt_encode({"email":email,"name":item.get("name",""),"role":item.get("role","user")})
    return jsonify({"success":True,"token":token,
                    "user":{"email":email,"name":item.get("name",""),"role":item.get("role","user")}}), 200


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def me():
    return jsonify({"user": g.user}), 200


# ════════════════════════════════════════════════════════════════
#  CORE ROUTES
# ════════════════════════════════════════════════════════════════
@app.route("/")
def home():
    return jsonify({"status":"running","service":"FakeShield API v3",
                    "hf":bool(HF_API_TOKEN),"sns":bool(SNS_TOPIC_ARN)})

@app.route("/api/report", methods=["POST"])
@optional_auth
def submit_report():
    try:
        d          = request.get_json() or {}
        identifier = d.get("identifier","").strip()
        rtype      = d.get("tagType", d.get("type","")).strip()
        message    = d.get("message","").strip()
        user_email = g.user["email"] if g.user else None
        if not identifier: return jsonify({"error":"Identifier required"}), 400
        if rtype not in ["Scam","Spam","Genuine"]: return jsonify({"error":"type must be Scam/Spam/Genuine"}), 400
        if not message: return jsonify({"error":"Message required"}), 400
        report = db_create_report(identifier, rtype, message, user_email)
        stats  = db_stats(identifier)
        return jsonify({"success":True,"message":"Report submitted",
                        "currentRiskScore":stats["riskScore"],"report":report}), 201
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route("/api/lookup/<path:identifier>", methods=["GET"])
@optional_auth
def lookup(identifier):
    try:
        s = db_stats(identifier)
        if request.args.get("ai","true").lower() != "false":
            s["aiAnalysis"] = build_ai_analysis(identifier, s)
        if s["totalReports"] == 0:
            s["riskScore"] = round(sr.get("score",0)*100)
            s["message"] = "No community reports; AI heuristic analysis."
        return jsonify(s), 200
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route("/api/reports", methods=["GET"])
def get_reports():
    try:
        return jsonify(db_all_reports(request.args.get("limit",100,type=int))), 200
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route("/api/stats", methods=["GET"])
def get_stats():
    try: return jsonify(db_dashboard()), 200
    except Exception as e: return jsonify({"error":str(e)}), 500

@app.route("/api/reports/<path:identifier>", methods=["GET"])
def id_reports(identifier):
    try: return jsonify(db_stats(identifier)["reports"]), 200
    except Exception as e: return jsonify({"error":str(e)}), 500

@app.errorhandler(404)
def nf(_): return jsonify({"error":"Not found"}), 404

@app.errorhandler(500)
def ie(_): return jsonify({"error":"Server error"}), 500


if __name__ == "__main__":
    init_dynamo()
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG","False") == "True"
    print(f"\n{'═'*52}")
    print(f"  FakeShield API v3.0")
    print(f"  Region   : {AWS_REGION}")
    print(f"  DynamoDB : {REPORTS_TABLE} / {USERS_TABLE}")
    print(f"  SNS      : {SNS_TOPIC_ARN or '✗ not set'}")
    print(f"  HF Token : {'✓' if HF_API_TOKEN else '✗ not set'}")
    print(f"  JWT      : {'⚠ default!' if JWT_SECRET=='changeme_secret' else '✓'}")
    print(f"{'═'*52}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)

"""
FakeShield API v3.2
──────────────────────────────────────────────────────────────────
Backend: Flask + AWS DynamoDB + AWS SNS + MSG91 + ZeroBounce + Claude AI + JWT Auth
──────────────────────────────────────────────────────────────────
Required .env variables:
  AWS_ACCESS_KEY_ID=
  AWS_SECRET_ACCESS_KEY=
  AWS_REGION=ap-south-1
  DYNAMODB_REPORTS_TABLE=fakeshield_reports
  DYNAMODB_USERS_TABLE=fakeshield_users
  DYNAMODB_SEARCHES_TABLE=fakeshield_searches
  SNS_TOPIC_ARN=arn:aws:sns:ap-south-1:XXXX:FakeShieldAlerts
  MSG91_API_KEY=your_msg91_api_key
  ZEROBOUNCE_API_KEY=your_zerobounce_api_key
  ANTHROPIC_API_KEY=your_anthropic_api_key
  JWT_SECRET=your_super_secret_key_change_this
  PORT=5000

Risk Score Bands:
   0 – 25  → GREEN  (Safe)
  25 – 50  → YELLOW (Low Risk)
  50 – 75  → ORANGE (Medium Risk)
  75 – 100 → RED    (High Risk / Danger)
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
AWS_REGION          = os.getenv("AWS_REGION", "ap-south-1")
REPORTS_TABLE       = os.getenv("DYNAMODB_REPORTS_TABLE", "fakeshield_reports")
USERS_TABLE         = os.getenv("DYNAMODB_USERS_TABLE",   "fakeshield_users")
SEARCHES_TABLE      = os.getenv("DYNAMODB_SEARCHES_TABLE", "fakeshield_searches")
SNS_TOPIC_ARN       = os.getenv("SNS_TOPIC_ARN", "")
MSG91_API_KEY       = os.getenv("MSG91_API_KEY", "500664AZ6y1ESSL2Mh69b7689dP1")
ZEROBOUNCE_API_KEY  = os.getenv("ZEROBOUNCE_API_KEY", "0acf4783fb75484c9853ea91e34f2f0f")
ANTHROPIC_API_KEY   = os.getenv("ANTHROPIC_API_KEY", "")
JWT_SECRET          = os.getenv("JWT_SECRET", "changeme_secret")

MSG91_BASE          = "https://api.msg91.com/api/v5/hlr-lookup"
ZEROBOUNCE_BASE     = "https://api.zerobounce.net/v2/validate"

# ── Risk score colour bands ──────────────────────────────────────
#   0  – 25  : GREEN  (Safe)
#  25  – 50  : YELLOW (Low Risk)
#  50  – 75  : ORANGE (Medium Risk)
#  75  – 100 : RED    (Danger)
def risk_band(score: float) -> str:
    if score < 25:
        return "green"
    elif score < 50:
        return "yellow"
    elif score < 75:
        return "orange"
    else:
        return "danger"


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


dynamodb        = boto3.resource("dynamodb", **_aws_kw())
sns_client      = boto3.client("sns",        **_aws_kw())
reports_table   = dynamodb.Table(REPORTS_TABLE)
users_table     = dynamodb.Table(USERS_TABLE)
searches_table  = dynamodb.Table(SEARCHES_TABLE)


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
    # ── Searches: PK=search_id ──────────────────────────────────
    _create_table_if_missing(
        SEARCHES_TABLE,
        key_schema=[{"AttributeName": "search_id", "KeyType": "HASH"}],
        attr_defs=[{"AttributeName": "search_id", "AttributeType": "S"}],
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
#  IDENTIFIER TYPE DETECTION
# ════════════════════════════════════════════════════════════════
def detect_id_type(v: str) -> str:
    """Detect if identifier is email or phone number"""
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v): 
        return "email"
    # Remove common phone formatting characters
    clean = re.sub(r"[\s\-().+]", "", v)
    if re.match(r"^\d{7,15}$", clean):
        return "phone"
    return "unknown"


# ════════════════════════════════════════════════════════════════
#  MSG91 API (Phone Number Validation via HLR Lookup)
# ════════════════════════════════════════════════════════════════
def msg91_validate(phone: str) -> dict:
    """
    Validate phone number using MSG91 HLR Lookup API.
    Docs: https://docs.msg91.com/reference/hlr-lookup
    Returns: dict with validation results
    """
    try:
        clean_phone = re.sub(r"[\s\-().+]", "", phone)
        # Ensure E.164 format (add country code if missing)
        if not clean_phone.startswith("+"):
            clean_phone = "+" + clean_phone

        headers = {
            "authkey": MSG91_API_KEY,
            "Content-Type": "application/json"
        }
        payload = {"number": clean_phone}

        response = requests.post(MSG91_BASE, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        # MSG91 HLR returns status field: "success" or error
        if data.get("type") == "success" or data.get("status") == "1":
            hlr = data.get("data", data)  # some versions wrap in "data"
            return {
                "valid": True,
                "number": clean_phone,
                "international_format": hlr.get("international_format", clean_phone),
                "local_format": hlr.get("local_format", ""),
                "country_prefix": hlr.get("country_prefix", ""),
                "country_code": hlr.get("country_code", ""),
                "country_name": hlr.get("country_name", ""),
                "location": hlr.get("location", ""),
                "carrier": hlr.get("carrier", hlr.get("network", "")),
                "line_type": hlr.get("line_type", hlr.get("type", "")),
                "ported": hlr.get("ported", False),
                "roaming": hlr.get("roaming", False),
            }
        else:
            return {
                "valid": False,
                "error": data.get("message", data.get("msg", "Invalid phone number"))
            }

    except Exception as e:
        print(f"[MSG91 Error] {e}")
        return {
            "valid": False,
            "error": f"API Error: {str(e)}"
        }


# ════════════════════════════════════════════════════════════════
#  ZEROBOUNCE EMAIL VALIDATION
#  Docs: https://www.zerobounce.net/members/API
# ════════════════════════════════════════════════════════════════
def zerobounce_validate_email(email: str) -> dict:
    """
    Validate email using ZeroBounce API.
    Endpoint: GET https://api.zerobounce.net/v2/validate
    Returns: dict with validation and quality results
    """
    try:
        params = {
            "api_key": ZEROBOUNCE_API_KEY,
            "email": email,
            "ip_address": ""  # optional — leave blank
        }

        response = requests.get(ZEROBOUNCE_BASE, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        # ZeroBounce status values:
        # valid, invalid, catch-all, unknown, spamtrap, abuse, do_not_mail
        status       = data.get("status", "unknown").lower()
        sub_status   = data.get("sub_status", "").lower()
        deliverable  = status == "valid"
        disposable   = sub_status in ("disposable", "role_based_catch_all")
        role_based   = sub_status == "role_based"
        free_email   = data.get("free_email", False)

        # Derive quality_score (0.0 – 1.0) from ZeroBounce status
        quality_map = {
            "valid":       0.95,
            "catch-all":   0.55,
            "unknown":     0.40,
            "spamtrap":    0.05,
            "abuse":       0.05,
            "do_not_mail": 0.05,
            "invalid":     0.0,
        }
        quality_score = quality_map.get(status, 0.3)
        if sub_status == "disposable":
            quality_score = min(quality_score, 0.1)

        return {
            "valid":        deliverable,
            "status":       status,
            "sub_status":   sub_status,
            "deliverable":  "DELIVERABLE" if deliverable else "UNDELIVERABLE",
            "quality_score": quality_score,
            "is_disposable": disposable,
            "is_free_email": free_email,
            "is_role_email": role_based,
            "is_catchall":  status == "catch-all",
            "firstname":    data.get("firstname", ""),
            "lastname":     data.get("lastname", ""),
            "domain":       data.get("domain", ""),
            "mx_found":     data.get("mx_found", ""),
            "mx_record":    data.get("mx_record", ""),
            "smtp_provider": data.get("smtp_provider", ""),
            "did_you_mean": data.get("did_you_mean", ""),
        }

    except Exception as e:
        print(f"[ZeroBounce Error] {e}")
        return {
            "valid": False,
            "error": f"API Error: {str(e)}"
        }


# ════════════════════════════════════════════════════════════════
#  CLAUDE AI ANALYSIS  (Anthropic claude-sonnet-4-20250514)
# ════════════════════════════════════════════════════════════════
def call_claude(prompt: str) -> str:
    """Call Anthropic Claude API and return text response."""
    if not ANTHROPIC_API_KEY:
        return ""
    try:
        headers = {
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 400,
            "messages": [{"role": "user", "content": prompt}]
        }
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers, json=payload, timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"].strip()
    except Exception as e:
        print(f"[Claude API Error] {e}")
        return ""


def build_ai_analysis(identifier: str, stats: dict) -> dict:
    """
    Build analysis using MSG91 (phones) or ZeroBounce (emails) for
    hard data, then call Claude for the narrative risk summary.
    """
    scam    = stats.get("scamCount", 0)
    spam    = stats.get("spamCount", 0)
    genuine = stats.get("genuineCount", 0)
    total   = stats.get("totalReports", 0)
    risk    = stats.get("riskScore", 0)
    band    = risk_band(risk)

    id_type  = detect_id_type(identifier)
    flags    = []
    api_data = {}

    # ── EMAIL ──────────────────────────────────────────────────
    if id_type == "email":
        result   = zerobounce_validate_email(identifier)
        api_data = result

        if result.get("error"):
            flags.append({"label": "Email validation unavailable", "level": "warning"})
        else:
            status  = result.get("status", "unknown")
            quality = result.get("quality_score", 0)

            if result.get("valid"):
                flags.append({"label": f"Email Deliverable ({int(quality*100)}% quality)", "level": "safe"})
            else:
                flags.append({"label": f"Email {status.upper()} – Not Deliverable", "level": "danger"})

            if result.get("is_disposable"):
                flags.append({"label": "Disposable / Temporary Email", "level": "danger"})
            if result.get("is_catchall"):
                flags.append({"label": "Catch-All Domain", "level": "warning"})
            if result.get("is_role_email"):
                flags.append({"label": "Role-Based Email (admin@, info@…)", "level": "warning"})
            if result.get("is_free_email"):
                flags.append({"label": "Free Email Provider", "level": "warning"})
            if result.get("sub_status") in ("spamtrap", "abuse"):
                flags.append({"label": f"Flagged: {result['sub_status'].upper()}", "level": "danger"})
            if result.get("did_you_mean"):
                flags.append({"label": f"Did you mean: {result['did_you_mean']}?", "level": "info"})

    # ── PHONE ──────────────────────────────────────────────────
    elif id_type == "phone":
        result   = msg91_validate(identifier)
        api_data = result

        if result.get("error"):
            flags.append({"label": "Phone validation unavailable", "level": "warning"})
        elif not result.get("valid"):
            flags.append({"label": "Invalid / Unreachable Number", "level": "danger"})
        else:
            country   = result.get("country_name", "Unknown")
            carrier   = result.get("carrier", "Unknown")
            line_type = result.get("line_type", "")

            flags.append({"label": f"Valid {country} Number", "level": "safe"})
            if carrier and carrier != "Unknown":
                flags.append({"label": f"Carrier: {carrier}", "level": "info"})
            if line_type:
                lt = line_type.lower()
                if lt in ("mobile", "cell"):
                    flags.append({"label": "Mobile Number", "level": "safe"})
                elif lt in ("landline", "fixed"):
                    flags.append({"label": "Landline Number", "level": "info"})
                elif lt == "voip":
                    flags.append({"label": "VOIP Number", "level": "warning"})
            if result.get("ported"):
                flags.append({"label": "Number Has Been Ported", "level": "warning"})
            if result.get("roaming"):
                flags.append({"label": "Number Currently Roaming", "level": "info"})
    else:
        flags.append({"label": "Unknown Identifier Type", "level": "warning"})

    # ── COMMUNITY REPORTS ──────────────────────────────────────
    if scam > 0:
        flags.append({"label": f"{scam} Scam Report(s)", "level": "danger"})
    if spam > 0:
        flags.append({"label": f"{spam} Spam Report(s)", "level": "warning"})
    if genuine > 0:
        flags.append({"label": f"{genuine} Genuine Report(s)", "level": "safe"})

    # ── RISK VERDICT ───────────────────────────────────────────
    verdict_map = {
        "green":  "SAFE",
        "yellow": "LOW RISK",
        "orange": "MEDIUM RISK",
        "danger": "HIGH RISK",
    }
    verdict = verdict_map[band]

    # ── CLAUDE NARRATIVE ───────────────────────────────────────
    ai_summary = ""
    if ANTHROPIC_API_KEY:
        flag_labels = ", ".join(f["label"] for f in flags) or "none"
        prompt = (
            f"You are a fraud-detection assistant. Analyse this identifier in 2-3 concise sentences.\n"
            f"Identifier : {identifier}\n"
            f"Type       : {id_type}\n"
            f"Risk score : {risk}/100 ({verdict})\n"
            f"Risk band  : {band}\n"
            f"Reports    : {scam} scam, {spam} spam, {genuine} genuine (total {total})\n"
            f"Signals    : {flag_labels}\n"
            f"Provide a plain-English risk summary and advice for the recipient."
        )
        ai_summary = call_claude(prompt)

    if not ai_summary:
        # Fallback deterministic summary
        if id_type == "email":
            q = int(api_data.get("quality_score", 0) * 100)
            d = api_data.get("deliverable", "UNKNOWN")
            ai_summary = f"{verdict}. Email quality: {q}%. Deliverability: {d}. Community reports: {total}."
        elif id_type == "phone":
            v = "Valid" if api_data.get("valid") else "Invalid"
            c = api_data.get("country_name", "Unknown")
            ai_summary = f"{verdict}. {v} {c} number. Community reports: {total}."
        else:
            ai_summary = f"{verdict}. Unknown identifier. Community reports: {total}."

    return {
        "verdict":          verdict,
        "riskBand":         band,
        "summary":          ai_summary,
        "flags":            flags[:8],
        "identifierType":   id_type,
        "apiData":          api_data,
        "analysisSource":   (
            "MSG91" if id_type == "phone"
            else ("ZeroBounce" if id_type == "email" else "None")
        ),
        "aiNarrative":      bool(ai_summary and ANTHROPIC_API_KEY),
    }
# ════════════════════════════════════════════════════════════════
#  SEARCH TRACKING
# ════════════════════════════════════════════════════════════════
def db_log_search(identifier: str, user_email: str = None):
    """Log search/lookup activity to DynamoDB"""
    try:
        search_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        item = {
            "search_id": search_id,
            "identifier": identifier,
            "searched_by": user_email or "anonymous",
            "searched_at": timestamp,
            "id_type": detect_id_type(identifier)
        }
        
        searches_table.put_item(Item=item)
        return item
    except Exception as e:
        print(f"[Search Log Error] {e}")
        return None


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
            "genuineCount":ge,"riskScore":risk,"scamScore":risk,"riskBand":risk_band(risk),
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
    return jsonify({"status":"running","service":"FakeShield API v3.2",
                    "msg91":bool(MSG91_API_KEY),"zerobounce":bool(ZEROBOUNCE_API_KEY),"claude":bool(ANTHROPIC_API_KEY),
                    "sns":bool(SNS_TOPIC_ARN)})

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
        # Log the search
        user_email = g.user["email"] if g.user else None
        db_log_search(identifier, user_email)
        
        # Get stats
        s = db_stats(identifier)
        
        # Build AI analysis (unless disabled)
        if request.args.get("ai","true").lower() != "false":
            s["aiAnalysis"] = build_ai_analysis(identifier, s)
        
        # If no reports, calculate risk from API validation
        if s["totalReports"] == 0:
            id_type = detect_id_type(identifier)
            if id_type == "email":
                email_data = zerobounce_validate_email(identifier)
                quality = email_data.get("quality_score", 0.5)
                # Convert quality to risk (inverse relationship)
                s["riskScore"] = round((1 - quality) * 50)  # 0-50 range for no reports
            elif id_type == "phone":
                phone_data = msg91_validate(identifier)
                if not phone_data.get("valid", False):
                    s["riskScore"] = 40  # Invalid number = medium risk
                else:
                    s["riskScore"] = 10  # Valid number, no reports = low risk
            s["message"] = "API validation analysis (no community reports)"
        
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
    print(f"\n{'═'*60}")
    print(f"  FakeShield API v3.2")
    print(f"  Region      : {AWS_REGION}")
    print(f"  DynamoDB    : {REPORTS_TABLE} / {USERS_TABLE} / {SEARCHES_TABLE}")
    print(f"  SNS         : {SNS_TOPIC_ARN or '✗ not set'}")
    print(f"  MSG91       : {'✓' if MSG91_API_KEY else '✗ not set'}")
    print(f"  ZeroBounce  : {'✓' if ZEROBOUNCE_API_KEY else '✗ not set'}")
    print(f"  Claude AI   : {'✓' if ANTHROPIC_API_KEY else '✗ not set'}")
    print(f"  JWT         : {'⚠ default!' if JWT_SECRET=='changeme_secret' else '✓'}")
    print(f"{'═'*60}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)

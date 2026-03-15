"""
FakeShield API v3.2.1 - Fixed Numverify API Integration
──────────────────────────────────────────────────────────────────
Backend: Flask + AWS DynamoDB + AWS SNS + Numverify + AbstractAPI + JWT Auth
──────────────────────────────────────────────────────────────────
Risk Score Scale (INVERTED - Higher is Better):
  100-70  = SAFE (Good/Trusted)
  70-40   = MEDIUM RISK (Possibly Suspicious)
  40-10   = DANGER (High Risk)
  10-0    = EXTREME DANGER (Very High Risk)
──────────────────────────────────────────────────────────────────
IMPORTANT: Numverify Free Tier
  - Use HTTP (not HTTPS): http://apilayer.net/api/validate
  - If you have paid plan, use: https://apilayer.net/api/validate
  - Free tier has rate limits (250 requests/month)
──────────────────────────────────────────────────────────────────
Required .env variables:
  AWS_ACCESS_KEY_ID=
  AWS_SECRET_ACCESS_KEY=
  AWS_REGION=ap-south-1
  DYNAMODB_REPORTS_TABLE=fakeshield_reports
  DYNAMODB_USERS_TABLE=fakeshield_users
  DYNAMODB_SEARCHES_TABLE=fakeshield_searches
  SNS_TOPIC_ARN=arn:aws:sns:ap-south-1:XXXX:FakeShieldAlerts
  NUMVERIFY_API_KEY=64b1ebe2c88531cfdef4a71c318f3811
  ABSTRACTAPI_EMAIL_KEY=0e6bb95788544355ad0c2366cc44ef77
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
AWS_REGION          = os.getenv("AWS_REGION", "ap-south-1")
REPORTS_TABLE       = os.getenv("DYNAMODB_REPORTS_TABLE", "fakeshield_reports")
USERS_TABLE         = os.getenv("DYNAMODB_USERS_TABLE",   "fakeshield_users")
SEARCHES_TABLE      = os.getenv("DYNAMODB_SEARCHES_TABLE", "fakeshield_searches")
SNS_TOPIC_ARN       = os.getenv("SNS_TOPIC_ARN", "")
NUMVERIFY_API_KEY   = os.getenv("NUMVERIFY_API_KEY", "64b1ebe2c88531cfdef4a71c318f3811")
ABSTRACTAPI_EMAIL_KEY = os.getenv("ABSTRACTAPI_EMAIL_KEY", "0e6bb95788544355ad0c2366cc44ef77")
JWT_SECRET          = os.getenv("JWT_SECRET", "changeme_secret")

# Numverify: Use HTTP for free tier, HTTPS for paid plans
NUMVERIFY_USE_HTTPS = os.getenv("NUMVERIFY_HTTPS", "false").lower() == "true"
NUMVERIFY_BASE      = f"{'https' if NUMVERIFY_USE_HTTPS else 'http'}://apilayer.net/api/validate"
ABSTRACTAPI_BASE    = "https://emailvalidation.abstractapi.com/v1/"


# ════════════════════════════════════════════════════════════════
#  AWS CLIENTS
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
    _create_table_if_missing(
        REPORTS_TABLE,
        key_schema=[{"AttributeName": "identifier", "KeyType": "HASH"},
                    {"AttributeName": "report_id",  "KeyType": "RANGE"}],
        attr_defs=[{"AttributeName": "identifier", "AttributeType": "S"},
                   {"AttributeName": "report_id",  "AttributeType": "S"}],
    )
    _create_table_if_missing(
        USERS_TABLE,
        key_schema=[{"AttributeName": "email", "KeyType": "HASH"}],
        attr_defs=[{"AttributeName": "email", "AttributeType": "S"}],
    )
    _create_table_if_missing(
        SEARCHES_TABLE,
        key_schema=[{"AttributeName": "search_id", "KeyType": "HASH"}],
        attr_defs=[{"AttributeName": "search_id", "AttributeType": "S"}],
    )


# ════════════════════════════════════════════════════════════════
#  JWT AUTH
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
    clean = re.sub(r"[\s\-().+]", "", v)
    if re.match(r"^\d{7,15}$", clean):
        return "phone"
    return "unknown"


# ════════════════════════════════════════════════════════════════
#  NUMVERIFY API (WITH BETTER ERROR HANDLING)
# ════════════════════════════════════════════════════════════════
def numverify_validate(phone: str) -> dict:
    """
    Validate phone number using Numverify API
    Returns basic validation on API failure (graceful degradation)
    """
    try:
        clean_phone = re.sub(r"[\s\-().+]", "", phone)
        
        params = {
            "access_key": NUMVERIFY_API_KEY,
            "number": clean_phone,
            "format": 1
        }
        
        print(f"[Numverify] Calling {NUMVERIFY_BASE} with number: {clean_phone}")
        response = requests.get(NUMVERIFY_BASE, params=params, timeout=15)
        
        # Debug response
        print(f"[Numverify] Status: {response.status_code}")
        
        # Handle 403 Forbidden specifically
        if response.status_code == 403:
            print("[Numverify] 403 Forbidden - API key may be invalid or free tier HTTPS restriction")
            print("[Numverify] Tip: Free tier requires HTTP, not HTTPS")
            # Return fallback validation
            return fallback_phone_validation(clean_phone)
        
        response.raise_for_status()
        data = response.json()
        
        # Check if API returned an error
        if "error" in data:
            error_info = data["error"]
            print(f"[Numverify] API Error: {error_info}")
            return fallback_phone_validation(clean_phone)
        
        if data.get("valid"):
            return {
                "valid": True,
                "number": data.get("number", ""),
                "local_format": data.get("local_format", ""),
                "international_format": data.get("international_format", ""),
                "country_prefix": data.get("country_prefix", ""),
                "country_code": data.get("country_code", ""),
                "country_name": data.get("country_name", ""),
                "location": data.get("location", ""),
                "carrier": data.get("carrier", ""),
                "line_type": data.get("line_type", ""),
                "source": "numverify"
            }
        else:
            return {"valid": False, "error": "Invalid phone number", "source": "numverify"}
            
    except requests.exceptions.Timeout:
        print(f"[Numverify] Timeout - using fallback validation")
        return fallback_phone_validation(clean_phone)
    except requests.exceptions.RequestException as e:
        print(f"[Numverify] Request Error: {e} - using fallback validation")
        return fallback_phone_validation(clean_phone)
    except Exception as e:
        print(f"[Numverify] Unexpected Error: {e} - using fallback validation")
        return fallback_phone_validation(clean_phone)


def fallback_phone_validation(clean_phone: str) -> dict:
    """
    Fallback phone validation when Numverify API fails
    Uses basic pattern matching for common formats
    """
    # Remove all non-digits
    digits_only = re.sub(r"\D", "", clean_phone)
    
    # Basic validation: 7-15 digits
    if 7 <= len(digits_only) <= 15:
        # Try to detect country from prefix
        country = "Unknown"
        if digits_only.startswith("1"):
            country = "United States/Canada"
        elif digits_only.startswith("44"):
            country = "United Kingdom"
        elif digits_only.startswith("91"):
            country = "India"
        elif digits_only.startswith("86"):
            country = "China"
        elif digits_only.startswith("81"):
            country = "Japan"
        elif digits_only.startswith("61"):
            country = "Australia"
        
        return {
            "valid": True,
            "number": digits_only,
            "local_format": clean_phone,
            "international_format": f"+{digits_only}",
            "country_name": country,
            "carrier": "Unknown (API unavailable)",
            "line_type": "Unknown",
            "source": "fallback",
            "note": "Numverify API unavailable - using basic validation"
        }
    else:
        return {
            "valid": False,
            "error": "Invalid phone number format",
            "source": "fallback"
        }


# ════════════════════════════════════════════════════════════════
#  ABSTRACTAPI EMAIL VALIDATION
# ════════════════════════════════════════════════════════════════
def abstractapi_validate_email(email: str) -> dict:
    """Validate and get reputation for email using AbstractAPI"""
    try:
        params = {"api_key": ABSTRACTAPI_EMAIL_KEY, "email": email}
        response = requests.get(ABSTRACTAPI_BASE, params=params, timeout=15)
        
        print(f"[AbstractAPI] Status: {response.status_code}")
        
        if response.status_code == 403:
            print("[AbstractAPI] 403 Forbidden - API key may be invalid")
            return fallback_email_validation(email)
        
        response.raise_for_status()
        data = response.json()
        
        return {
            "valid": data.get("is_valid_format", {}).get("value", False),
            "deliverable": data.get("deliverability", "UNKNOWN"),
            "quality_score": data.get("quality_score", 0),
            "is_disposable": data.get("is_disposable_email", {}).get("value", False),
            "is_free_email": data.get("is_free_email", {}).get("value", False),
            "is_role_email": data.get("is_role_email", {}).get("value", False),
            "is_catchall": data.get("is_catchall_email", {}).get("value", False),
            "is_mx_found": data.get("is_mx_found", {}).get("value", False),
            "is_smtp_valid": data.get("is_smtp_valid", {}).get("value", False),
            "domain": data.get("domain", ""),
            "smtp_provider": data.get("smtp_provider", ""),
            "source": "abstractapi"
        }
    except Exception as e:
        print(f"[AbstractAPI] Error: {e} - using fallback")
        return fallback_email_validation(email)


def fallback_email_validation(email: str) -> dict:
    """Fallback email validation using regex"""
    # Basic email regex
    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    valid = bool(re.match(email_pattern, email))
    
    # Check for common disposable domains
    disposable_domains = ["tempmail.com", "guerrillamail.com", "10minutemail.com", 
                         "throwaway.email", "mailinator.com"]
    domain = email.split("@")[1] if "@" in email else ""
    is_disposable = domain.lower() in disposable_domains
    
    # Check for free providers
    free_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
    is_free = domain.lower() in free_domains
    
    return {
        "valid": valid,
        "deliverable": "UNKNOWN",
        "quality_score": 0.5 if valid else 0,
        "is_disposable": is_disposable,
        "is_free_email": is_free,
        "is_role_email": email.startswith(("admin@", "info@", "support@", "contact@")),
        "domain": domain,
        "source": "fallback",
        "note": "AbstractAPI unavailable - using basic validation"
    }


# ════════════════════════════════════════════════════════════════
#  TRUST SCORE CALCULATION (INVERTED - 100=SAFE, 0=DANGER)
# ════════════════════════════════════════════════════════════════
def calculate_trust_score(scam_count: int, spam_count: int, genuine_count: int, total: int) -> float:
    """Calculate trust score: 100=safe, 0=extreme danger"""
    if total == 0:
        return 50.0
    
    scam_weight = -50
    spam_weight = -30
    genuine_weight = 20
    
    weighted_score = ((scam_count * scam_weight) + (spam_count * spam_weight) + (genuine_count * genuine_weight)) / total
    trust_score = 80 + weighted_score
    return round(max(0, min(100, trust_score)), 2)


def get_risk_level(trust_score: float) -> str:
    """Convert trust score to risk level"""
    if trust_score >= 70:
        return "SAFE"
    elif trust_score >= 40:
        return "MEDIUM RISK"
    elif trust_score >= 10:
        return "DANGER"
    else:
        return "EXTREME DANGER"


# ════════════════════════════════════════════════════════════════
#  AI ANALYSIS
# ════════════════════════════════════════════════════════════════
def build_ai_analysis(identifier: str, stats: dict) -> dict:
    scam = stats.get("scamCount", 0)
    spam = stats.get("spamCount", 0)
    genuine = stats.get("genuineCount", 0)
    total = stats.get("totalReports", 0)
    trust_score = stats.get("trustScore", 50)

    id_type = detect_id_type(identifier)
    flags = []
    api_data = {}
    
    if id_type == "email":
        email_result = abstractapi_validate_email(identifier)
        api_data = email_result
        
        # Check if using fallback
        if email_result.get("source") == "fallback":
            flags.append({"label": "API Unavailable (Basic Check)", "level": "warning"})
        
        if not email_result.get("valid", False):
            flags.append({"label": "Invalid Email Format", "level": "danger"})
        else:
            quality = email_result.get("quality_score", 0)
            if quality >= 0.8:
                flags.append({"label": f"High Quality Email ({int(quality*100)}%)", "level": "safe"})
            elif quality >= 0.5:
                flags.append({"label": f"Medium Quality Email ({int(quality*100)}%)", "level": "warning"})
            else:
                flags.append({"label": f"Low Quality Email ({int(quality*100)}%)", "level": "danger"})
            
            deliverable = email_result.get("deliverable", "UNKNOWN")
            if deliverable == "DELIVERABLE":
                flags.append({"label": "Email is Deliverable", "level": "safe"})
            elif deliverable == "UNDELIVERABLE":
                flags.append({"label": "Email Undeliverable", "level": "danger"})
            
            if email_result.get("is_disposable", False):
                flags.append({"label": "Disposable Email Address", "level": "danger"})
            if email_result.get("is_free_email", False):
                flags.append({"label": "Free Email Provider", "level": "info"})
            if email_result.get("is_role_email", False):
                flags.append({"label": "Role-based Email", "level": "warning"})
    
    elif id_type == "phone":
        phone_result = numverify_validate(identifier)
        api_data = phone_result
        
        # Check if using fallback
        if phone_result.get("source") == "fallback":
            flags.append({"label": "API Unavailable (Basic Check)", "level": "warning"})
        
        if not phone_result.get("valid", False):
            flags.append({"label": "Invalid Phone Number", "level": "danger"})
        else:
            country = phone_result.get("country_name", "Unknown")
            carrier = phone_result.get("carrier", "Unknown")
            line_type = phone_result.get("line_type", "Unknown")
            
            flags.append({"label": f"Valid {country} Number", "level": "safe"})
            if carrier and carrier != "Unknown" and "unavailable" not in carrier.lower():
                flags.append({"label": f"Carrier: {carrier}", "level": "info"})
            
            if line_type and line_type != "Unknown":
                if line_type.lower() in ["mobile", "cell"]:
                    flags.append({"label": "Mobile Number", "level": "safe"})
                elif line_type.lower() in ["landline", "fixed"]:
                    flags.append({"label": "Landline Number", "level": "info"})
                elif line_type.lower() == "voip":
                    flags.append({"label": "VOIP Number", "level": "warning"})
    else:
        flags.append({"label": "Unknown Identifier Type", "level": "warning"})

    if scam > 0:
        flags.append({"label": f"{scam} Scam Report(s)", "level": "danger"})
    if spam > 0:
        flags.append({"label": f"{spam} Spam Report(s)", "level": "warning"})
    if genuine > 0:
        flags.append({"label": f"{genuine} Genuine Report(s)", "level": "safe"})

    verdict = get_risk_level(trust_score)

    if id_type == "email":
        quality = api_data.get("quality_score", 0)
        deliverable = api_data.get("deliverable", "UNKNOWN")
        summary = f"{verdict}. Quality: {int(quality*100)}%. Deliverable: {deliverable}. Reports: {total}."
    elif id_type == "phone":
        valid = "Valid" if api_data.get("valid", False) else "Invalid"
        country = api_data.get("country_name", "Unknown")
        summary = f"{verdict}. {valid} {country} number. Reports: {total}."
    else:
        summary = f"{verdict}. Unknown type. Reports: {total}."

    return {
        "verdict": verdict,
        "summary": summary,
        "flags": flags[:8],
        "identifierType": id_type,
        "apiData": api_data,
        "analysisSource": api_data.get("source", "unknown")
    }


# ════════════════════════════════════════════════════════════════
#  SEARCH TRACKING
# ════════════════════════════════════════════════════════════════
def db_log_search(identifier: str, trust_score: float, user_email: str = None, api_result: dict = None):
    try:
        search_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        id_type = detect_id_type(identifier)
        
        item = {
            "search_id": search_id,
            "identifier": identifier,
            "searched_by": user_email or "anonymous",
            "searched_at": timestamp,
            "id_type": id_type,
            "trust_score": trust_score,
            "risk_level": get_risk_level(trust_score)
        }
        
        if api_result:
            item["api_source"] = api_result.get("source", "unknown")
            if id_type == "email":
                item["email_quality"] = api_result.get("quality_score", 0)
                item["deliverable"] = api_result.get("deliverable", "UNKNOWN")
                item["is_disposable"] = api_result.get("is_disposable", False)
            elif id_type == "phone":
                item["phone_valid"] = api_result.get("valid", False)
                item["country"] = api_result.get("country_name", "Unknown")
                item["carrier"] = api_result.get("carrier", "Unknown")
                item["line_type"] = api_result.get("line_type", "Unknown")
        
        searches_table.put_item(Item=item)
        print(f"✓ Search logged: {identifier} (Trust: {trust_score})")
        return item
    except Exception as e:
        print(f"[Search Log Error] {e}")
        return None


# ════════════════════════════════════════════════════════════════
#  CRUD OPERATIONS
# ════════════════════════════════════════════════════════════════
def db_create_report(identifier, rtype, message, user_email=None):
    rid = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    item = {"identifier": identifier, "report_id": rid, "type": rtype, "message": message, 
            "created_at": ts, "reported_by": user_email or "anonymous"}
    reports_table.put_item(Item=item)
    if rtype == "Scam":
        sns_notify(f"[FakeShield] SCAM: {identifier}", 
                   f"ID: {identifier}\nBy: {user_email or 'anon'}\nMsg: {message}")
    return {**item, "tagType": rtype, "createdAt": ts}


def db_stats(identifier):
    items = reports_table.query(KeyConditionExpression=Key("identifier").eq(identifier)).get("Items", [])
    sc = sum(1 for r in items if r.get("type", "").lower() == "scam")
    sp = sum(1 for r in items if r.get("type", "").lower() == "spam")
    ge = sum(1 for r in items if r.get("type", "").lower() == "genuine")
    tot = len(items)
    trust_score = calculate_trust_score(sc, sp, ge, tot)
    
    reports = sorted([
        {"id": r.get("report_id"), "identifier": r.get("identifier"), "tagType": r.get("type"),
         "message": r.get("message"), "createdAt": r.get("created_at"), "reportedBy": r.get("reported_by")}
        for r in items
    ], key=lambda x: x.get("createdAt", ""), reverse=True)
    
    return {
        "identifier": identifier,
        "totalReports": tot,
        "scamCount": sc,
        "spamCount": sp,
        "genuineCount": ge,
        "trustScore": trust_score,
        "riskScore": trust_score,
        "scamScore": 100 - trust_score,
        "riskLevel": get_risk_level(trust_score),
        "tags": list(set(r.get("type", "") for r in items)),
        "reports": reports
    }


def db_all_reports(limit=100):
    resp = reports_table.scan(Limit=min(limit, 1000))
    items = resp.get("Items", [])
    return sorted([
        {"id": r.get("report_id"), "identifier": r.get("identifier"), "tagType": r.get("type"),
         "message": r.get("message"), "createdAt": r.get("created_at"), "reportedBy": r.get("reported_by")}
        for r in items
    ], key=lambda x: x.get("createdAt", ""), reverse=True)[:limit]


def db_dashboard():
    items = reports_table.scan(ProjectionExpression="#t", ExpressionAttributeNames={"#t": "type"}).get("Items", [])
    total = len(items)
    sc = sum(1 for r in items if r.get("type") == "Scam")
    sp = sum(1 for r in items if r.get("type") == "Spam")
    ge = sum(1 for r in items if r.get("type") == "Genuine")
    ids = len(set(r.get("identifier", "") for r in reports_table.scan(ProjectionExpression="identifier").get("Items", [])))
    return {"totalReports": total, "scamCount": sc, "spamCount": sp, "genuineCount": ge, "uniqueIdentifiers": ids}


# ════════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ════════════════════════════════════════════════════════════════
@app.route("/api/auth/register", methods=["POST"])
def register():
    d = request.get_json() or {}
    email = d.get("email", "").strip().lower()
    password = d.get("password", "")
    name = d.get("name", "").strip()
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Invalid email"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be ≥ 6 characters"}), 400
    if users_table.get_item(Key={"email": email}).get("Item"):
        return jsonify({"error": "Email already registered"}), 409
    
    ts = datetime.now(timezone.utc).isoformat()
    uname = name or email.split("@")[0]
    users_table.put_item(Item={"email": email, "name": uname, "password": hash_pw(password), 
                                "created_at": ts, "role": "user"})
    sns_notify("[FakeShield] New user", f"Email: {email}\nTime: {ts}")
    token = jwt_encode({"email": email, "name": uname, "role": "user"})
    return jsonify({"success": True, "token": token, "user": {"email": email, "name": uname, "role": "user"}}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    d = request.get_json() or {}
    email = d.get("email", "").strip().lower()
    pw = d.get("password", "")
    
    if not email or not pw:
        return jsonify({"error": "Email and password required"}), 400
    
    item = users_table.get_item(Key={"email": email}).get("Item")
    if not item or not verify_pw(pw, item.get("password", "")):
        return jsonify({"error": "Invalid email or password"}), 401
    
    token = jwt_encode({"email": email, "name": item.get("name", ""), "role": item.get("role", "user")})
    return jsonify({"success": True, "token": token, 
                    "user": {"email": email, "name": item.get("name", ""), "role": item.get("role", "user")}}), 200


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def me():
    return jsonify({"user": g.user}), 200


# ════════════════════════════════════════════════════════════════
#  CORE ROUTES
# ════════════════════════════════════════════════════════════════
@app.route("/")
def home():
    return jsonify({
        "status": "running",
        "service": "FakeShield API v3.2.1",
        "riskScale": "100-70=SAFE | 70-40=MEDIUM | 40-10=DANGER | 10-0=EXTREME",
        "numverify": bool(NUMVERIFY_API_KEY),
        "numverify_protocol": "HTTPS" if NUMVERIFY_USE_HTTPS else "HTTP (free tier)",
        "abstractapi": bool(ABSTRACTAPI_EMAIL_KEY),
        "sns": bool(SNS_TOPIC_ARN)
    })


@app.route("/api/report", methods=["POST"])
@optional_auth
def submit_report():
    try:
        d = request.get_json() or {}
        identifier = d.get("identifier", "").strip()
        rtype = d.get("tagType", d.get("type", "")).strip()
        message = d.get("message", "").strip()
        user_email = g.user["email"] if g.user else None
        
        if not identifier:
            return jsonify({"error": "Identifier required"}), 400
        if rtype not in ["Scam", "Spam", "Genuine"]:
            return jsonify({"error": "type must be Scam/Spam/Genuine"}), 400
        if not message:
            return jsonify({"error": "Message required"}), 400
        
        report = db_create_report(identifier, rtype, message, user_email)
        stats = db_stats(identifier)
        
        return jsonify({
            "success": True,
            "message": "Report submitted",
            "currentTrustScore": stats["trustScore"],
            "currentRiskScore": stats["trustScore"],
            "riskLevel": stats["riskLevel"],
            "report": report
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/lookup/<path:identifier>", methods=["GET"])
@optional_auth
def lookup(identifier):
    try:
        user_email = g.user["email"] if g.user else None
        s = db_stats(identifier)
        
        ai_analysis = None
        api_data = None
        
        if request.args.get("ai", "true").lower() != "false":
            ai_analysis = build_ai_analysis(identifier, s)
            s["aiAnalysis"] = ai_analysis
            api_data = ai_analysis.get("apiData", {})
        
        if s["totalReports"] == 0:
            id_type = detect_id_type(identifier)
            
            if id_type == "email":
                email_data = abstractapi_validate_email(identifier)
                api_data = email_data
                quality = email_data.get("quality_score", 0.5)
                trust_score = round(20 + (quality * 70), 2)
                
                if email_data.get("is_disposable", False):
                    trust_score = max(10, trust_score - 40)
                if not email_data.get("valid", False):
                    trust_score = max(5, trust_score - 50)
                
                s["trustScore"] = trust_score
                s["riskScore"] = trust_score
                s["riskLevel"] = get_risk_level(trust_score)
                
            elif id_type == "phone":
                phone_data = numverify_validate(identifier)
                api_data = phone_data
                
                if not phone_data.get("valid", False):
                    trust_score = 20
                else:
                    line_type = phone_data.get("line_type", "").lower()
                    if line_type in ["mobile", "cell"]:
                        trust_score = 75
                    elif line_type == "voip":
                        trust_score = 45
                    else:
                        trust_score = 60
                
                s["trustScore"] = trust_score
                s["riskScore"] = trust_score
                s["riskLevel"] = get_risk_level(trust_score)
            else:
                s["trustScore"] = 50
                s["riskScore"] = 50
                s["riskLevel"] = "MEDIUM RISK"
            
            s["message"] = "API validation analysis (no community reports)"
        
        db_log_search(identifier=identifier, trust_score=s["trustScore"], 
                      user_email=user_email, api_result=api_data)
        
        return jsonify(s), 200
    except Exception as e:
        print(f"[Lookup Error] {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/reports", methods=["GET"])
def get_reports():
    try:
        return jsonify(db_all_reports(request.args.get("limit", 100, type=int))), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def get_stats():
    try:
        return jsonify(db_dashboard()), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/reports/<path:identifier>", methods=["GET"])
def id_reports(identifier):
    try:
        return jsonify(db_stats(identifier)["reports"]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/searches", methods=["GET"])
@optional_auth
def get_searches():
    try:
        limit = request.args.get("limit", 50, type=int)
        resp = searches_table.scan(Limit=min(limit, 1000))
        items = resp.get("Items", [])
        searches = sorted(items, key=lambda x: x.get("searched_at", ""), reverse=True)[:limit]
        return jsonify(searches), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(_):
    return jsonify({"error": "Server error"}), 500


if __name__ == "__main__":
    init_dynamo()
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "False") == "True"
    
    print(f"\n{'═'*70}")
    print(f"  FakeShield API v3.2.1 - Inverted Risk Score + Fallback Validation")
    print(f"  {'─'*68}")
    print(f"  Risk Scale  : 100-70=SAFE | 70-40=MEDIUM | 40-10=DANGER | 10-0=EXTREME")
    print(f"  Region      : {AWS_REGION}")
    print(f"  DynamoDB    : {REPORTS_TABLE} / {USERS_TABLE} / {SEARCHES_TABLE}")
    print(f"  SNS         : {SNS_TOPIC_ARN or '✗ not set'}")
    print(f"  Numverify   : {'✓' if NUMVERIFY_API_KEY else '✗ not set'} ({NUMVERIFY_BASE})")
    print(f"  AbstractAPI : {'✓' if ABSTRACTAPI_EMAIL_KEY else '✗ not set'}")
    print(f"  JWT         : {'⚠ default!' if JWT_SECRET=='changeme_secret' else '✓'}")
    print(f"  {'─'*68}")
    print(f"  NOTE: Free Numverify tier requires HTTP (not HTTPS)")
    print(f"        Set NUMVERIFY_HTTPS=true in .env if you have paid plan")
    print(f"{'═'*70}\n")
    
    app.run(host="0.0.0.0", port=port, debug=debug)

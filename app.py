"""
FakeShield API v4
Flask + DynamoDB + HuggingFace + AbstractAPI Email Reputation
"""

import os
import re
import uuid
import json
import time
import base64
import hashlib
import hmac
import requests
from datetime import datetime, timezone
from functools import wraps

import boto3
from boto3.dynamodb.conditions import Key
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# ------------------------------------------------
# CONFIG
# ------------------------------------------------

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")

REPORTS_TABLE = os.getenv("DYNAMODB_REPORTS_TABLE", "fakeshield_reports")
USERS_TABLE = os.getenv("DYNAMODB_USERS_TABLE", "fakeshield_users")

SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "")

HF_API_TOKEN = os.getenv("HF_API_TOKEN", "")

EMAIL_API_KEY = os.getenv("EMAIL_API_KEY", "")
EMAIL_API_URL = "https://emailreputation.abstractapi.com/v1/"

JWT_SECRET = os.getenv("JWT_SECRET", "change_this_secret")

HF_BASE = "https://api-inference.huggingface.co/models"

SPAM_MODEL = "cardiffnlp/twitter-roberta-base-offensive"
ZEROSHOT_MODEL = "MoritzLaurer/deberta-v3-large-zeroshot-v2.0"

# ------------------------------------------------
# AWS CLIENTS
# ------------------------------------------------

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)

reports_table = dynamodb.Table(REPORTS_TABLE)
users_table = dynamodb.Table(USERS_TABLE)

sns = boto3.client("sns", region_name=AWS_REGION)

# ------------------------------------------------
# JWT
# ------------------------------------------------


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt_encode(payload, exp=86400):

    payload["exp"] = int(time.time()) + exp

    header = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64u(json.dumps(payload).encode())

    sig = b64u(
        hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    )

    return f"{header}.{body}.{sig}"


def jwt_decode(token):

    header, body, sig = token.split(".")

    expected = b64u(
        hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    )

    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid token")

    payload = json.loads(base64.urlsafe_b64decode(body + "=="))

    if payload["exp"] < time.time():
        raise ValueError("Token expired")

    return payload


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        token = request.headers.get("Authorization", "").replace("Bearer ", "")

        if not token:
            return jsonify({"error": "Auth required"}), 401

        try:
            g.user = jwt_decode(token)
        except:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)

    return wrapper


# ------------------------------------------------
# PASSWORD
# ------------------------------------------------


def hash_pw(password):

    salt = os.urandom(16)

    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)

    return base64.b64encode(salt + h).decode()


def verify_pw(password, stored):

    decoded = base64.b64decode(stored)

    salt = decoded[:16]

    stored_hash = decoded[16:]

    new_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)

    return hmac.compare_digest(stored_hash, new_hash)


# ------------------------------------------------
# HELPERS
# ------------------------------------------------


def detect_id_type(v):

    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
        return "email"

    if re.match(r"^\+?[\d\s\-().]{7,20}$", v):
        return "phone"

    return "unknown"


# ------------------------------------------------
# EMAIL REPUTATION API
# ------------------------------------------------


def email_reputation(email):

    if not EMAIL_API_KEY:
        return {"status": "no_api_key"}

    try:

        r = requests.get(
            EMAIL_API_URL,
            params={"api_key": EMAIL_API_KEY, "email": email},
            timeout=10,
        )

        data = r.json()

        return {
            "deliverability": data.get("deliverability"),
            "is_disposable": data.get("is_disposable_email", {}).get("value"),
            "domain": data.get("domain"),
            "risk": data.get("risk"),
        }

    except Exception as e:

        print("Email API error:", e)

        return {"status": "error"}


# ------------------------------------------------
# HUGGINGFACE
# ------------------------------------------------


def hf_headers():

    headers = {"Content-Type": "application/json"}

    if HF_API_TOKEN:
        headers["Authorization"] = f"Bearer {HF_API_TOKEN}"

    return headers


def hf_spam(text):

    try:

        r = requests.post(
            f"{HF_BASE}/{SPAM_MODEL}",
            headers=hf_headers(),
            json={"inputs": text},
            timeout=20,
        )

        data = r.json()

        if isinstance(data[0], list):
            data = data[0]

        best = max(data, key=lambda x: x["score"])

        return best

    except Exception as e:

        print("HF error:", e)

        return {"label": "UNKNOWN", "score": 0}


def hf_zero_shot(text, labels):

    try:

        r = requests.post(
            f"{HF_BASE}/{ZEROSHOT_MODEL}",
            headers=hf_headers(),
            json={
                "inputs": text,
                "parameters": {"candidate_labels": labels},
            },
            timeout=20,
        )

        data = r.json()

        return dict(zip(data["labels"], data["scores"]))

    except Exception as e:

        print("HF zshot:", e)

        return {}


# ------------------------------------------------
# AI ANALYSIS
# ------------------------------------------------


def build_ai_analysis(identifier, stats):

    text = f"Message from {identifier}. Could it be phishing?"

    spam_result = hf_spam(text)

    zs = hf_zero_shot(
        text,
        [
            "phishing scam",
            "financial fraud",
            "spam marketing",
            "legitimate business",
        ],
    )

    return {
        "hfLabel": spam_result.get("label"),
        "hfConfidence": spam_result.get("score"),
        "categories": zs,
    }


# ------------------------------------------------
# DATABASE
# ------------------------------------------------


def db_create_report(identifier, rtype, message, user):

    rid = str(uuid.uuid4())

    item = {
        "identifier": identifier,
        "report_id": rid,
        "type": rtype,
        "message": message,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "reported_by": user,
    }

    reports_table.put_item(Item=item)

    return item


def db_stats(identifier):

    resp = reports_table.query(
        KeyConditionExpression=Key("identifier").eq(identifier)
    )

    items = resp.get("Items", [])

    scam = sum(1 for r in items if r["type"] == "Scam")
    spam = sum(1 for r in items if r["type"] == "Spam")
    genuine = sum(1 for r in items if r["type"] == "Genuine")

    total = len(items)

    risk = min(100, scam * 40 + spam * 20)

    return {
        "identifier": identifier,
        "totalReports": total,
        "scamCount": scam,
        "spamCount": spam,
        "genuineCount": genuine,
        "riskScore": risk,
        "reports": items,
    }


# ------------------------------------------------
# ROUTES
# ------------------------------------------------


@app.route("/")
def home():

    return jsonify({"service": "FakeShield API", "status": "running"})


@app.route("/api/report", methods=["POST"])
def report():

    data = request.json

    identifier = data.get("identifier")

    rtype = data.get("type")

    message = data.get("message")

    if not identifier:
        return jsonify({"error": "identifier required"}), 400

    report = db_create_report(identifier, rtype, message, "anonymous")

    return jsonify(report)


@app.route("/api/lookup/<path:identifier>")
def lookup(identifier):

    stats = db_stats(identifier)

    id_type = detect_id_type(identifier)

    if id_type == "email":

        stats["emailIntel"] = email_reputation(identifier)

    stats["aiAnalysis"] = build_ai_analysis(identifier, stats)

    return jsonify(stats)


@app.route("/api/stats")
def stats():

    resp = reports_table.scan()

    items = resp.get("Items", [])

    return jsonify({"totalReports": len(items)})


# ------------------------------------------------
# MAIN
# ------------------------------------------------

if __name__ == "__main__":

    port = int(os.getenv("PORT", 5000))

    print("FakeShield API running")

    app.run(host="0.0.0.0", port=port)

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from feature_extraction import extract_features
import requests
import os
from urllib.parse import urlparse
import ssl
import socket

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

model = joblib.load("model.pkl")

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")


# 🔍 GOOGLE CHECK (SAFE)
def check_google(url):
    try:
        if not GOOGLE_API_KEY:
            return False

        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

        payload = {
            "client": {"clientId": "phishguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        res = requests.post(api_url, json=payload, timeout=3)
        data = res.json()

        return "matches" in data

    except:
        return False


# 🔒 SSL CHECK
def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            return True
    except:
        return False


@app.route("/")
def home():
    return "PhishGuard Backend Running ✅"


# 🚀 MAIN API
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "No URL"}), 400

        # ML
        features = extract_features(url)
        prob = float(model.predict_proba([features])[0][1])

        # SAFE DEFAULTS
        google_flag = False
        ssl_flag = False
        domain_age = -1

        try:
            google_flag = check_google(url)
        except:
            pass

        try:
            domain = urlparse(url).netloc
            ssl_flag = check_ssl(domain)
        except:
            pass

        # SCORE
        score = prob * 100 * 0.5

        if google_flag:
            score += 30

        if not ssl_flag:
            score += 20

        result = "Phishing" if score > 60 else "Safe"

        return jsonify({
            "result": result,
            "confidence": float(round(prob * 100, 2)),
            "risk_score": int(score),
            "google_flag": bool(google_flag),
            "ssl": bool(ssl_flag),
            "domain_age": int(domain_age)
        })

    except Exception as e:
        return jsonify({
            "error": "Server error",
            "details": str(e)
        }), 500


if __name__ == "__main__":
    app.run(debug=True)
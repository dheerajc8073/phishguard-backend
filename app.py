from flask import Flask, request, jsonify
import joblib
from feature_extraction import extract_features
from flask_cors import CORS
import requests
import os
from urllib.parse import urlparse
import whois
from datetime import datetime
import ssl
import socket

app = Flask(__name__)
CORS(app)

model = joblib.load("model.pkl")

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")


# 🔍 GOOGLE CHECK
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

        res = requests.post(api_url, json=payload)
        data = res.json()

        return "matches" in data

    except:
        return False


# 🌐 DOMAIN AGE
def get_domain_age(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age = (datetime.now() - creation_date).days
        return age

    except:
        return -1


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


# 🚀 API
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL"}), 400

    # ML
    features = extract_features(url)
    prob = model.predict_proba([features])[0][1]

    # Extra checks
    google_flag = check_google(url)
    domain = urlparse(url).netloc
    ssl_flag = check_ssl(domain)
    domain_age = get_domain_age(url)

    # 🧠 SCORING ENGINE
    score = prob * 100 * 0.5

    if google_flag:
        score += 30

    if not ssl_flag:
        score += 20

    if domain_age != -1 and domain_age < 30:
        score += 30

    result = "Phishing" if score > 60 else "Safe"

    return jsonify({
        "result": result,
        "confidence": round(prob * 100, 2),
        "risk_score": int(score),
        "google_flag": google_flag,
        "ssl": ssl_flag,
        "domain_age": domain_age
    })


if __name__ == "__main__":
    app.run(debug=True)

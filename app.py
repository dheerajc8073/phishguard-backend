from flask import Flask, request, jsonify
import joblib
from feature_extraction import extract_features
from flask_cors import CORS
import requests
import os
from urllib.parse import urlparse

# 🔐 Load API key from environment
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

app = Flask(__name__)
CORS(app)

# Load ML model
model = joblib.load("model.pkl")


# ✅ Home route
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "Backend Running 🚀",
        "message": "Use /predict endpoint"
    })


# 🔍 Google Safe Browsing
def check_google_safe_browsing(url):
    try:
        if not GOOGLE_API_KEY:
            return False

        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

        payload = {
            "client": {
                "clientId": "phishguard",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        response = requests.post(api_url, json=payload, timeout=3)

        if response.status_code == 200 and response.json():
            return True
        return False

    except Exception:
        return False


# 🧠 Explain WHY (IMPROVED VERSION)
def explain_features(url):
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # 🔴 Suspicious keyword
    if any(word in url.lower() for word in ["login", "verify", "bank", "secure", "account"]):
        reasons.append("Contains sensitive keywords (login/verify/bank)")

    # 🔴 URL length
    if len(url) > 75:
        reasons.append("URL is unusually long")

    # 🔴 @ symbol
    if "@" in url:
        reasons.append("Contains @ symbol (possible redirect attack)")

    # 🔴 Too many hyphens
    if domain.count("-") > 3:
        reasons.append("Too many hyphens in domain")

    # 🔴 HTTP not HTTPS
    if url.startswith("http://"):
        reasons.append("Not using secure HTTPS")

    # 🔴 Too many dots (subdomains)
    if domain.count(".") > 3:
        reasons.append("Too many subdomains (suspicious structure)")

    # 🟢 If no issues
    if not reasons:
        reasons.append("No obvious phishing patterns detected")

    return reasons


# 🔥 MAIN PREDICT API
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # 1️⃣ Feature extraction
        features = extract_features(url)

        # 2️⃣ ML prediction
        prediction = model.predict([features])[0]
        probs = model.predict_proba([features])[0]

        phishing_index = list(model.classes_).index(1)
        prob = probs[phishing_index]  # 0 → 1

        # 3️⃣ Google Safe Browsing
        google_flag = check_google_safe_browsing(url)

        # 🔥 4️⃣ SMART DECISION
        if google_flag:
            final_result = "Phishing"
        elif prob > 0.7:
            final_result = "Phishing"
        else:
            final_result = "Safe"

        # 🔥 5️⃣ Risk Score
        risk_score = round(prob * 100)

        # 🔥 6️⃣ Explanation
        reasons = explain_features(url)

        return jsonify({
            "result": final_result,
            "confidence": round(prob * 100, 2),
            "risk_score": risk_score,
            "google_flag": google_flag,
            "reasons": reasons   # ✅ THIS WAS MISSING
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Run locally
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

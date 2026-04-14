from flask import Flask, request, jsonify
import joblib
from feature_extraction import extract_features
from flask_cors import CORS
import requests
import os
from urllib.parse import urlparse

# 🔐 API KEY (from Render env)
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

app = Flask(__name__)
CORS(app)

# ✅ Load model
model = joblib.load("model.pkl")


# 🔍 GOOGLE SAFE BROWSING
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

        res = requests.post(api_url, json=payload, timeout=3)

        return res.status_code == 200 and res.json()

    except:
        return False


# 🔥 BRAND PHISHING DETECTION
def detect_brand_phishing(url):
    domain = urlparse(url).netloc.lower()

    brands = [
        "amazon", "google", "facebook", "paypal",
        "instagram", "netflix", "bank", "sbi",
        "hdfc", "icici", "axis", "flipkart"
    ]

    for brand in brands:
        if brand in domain:
            if not domain.endswith(f"{brand}.com"):
                return True

    return False


# 🔥 SUSPICIOUS DOMAIN DETECTION
def detect_suspicious_domain(url):
    domain = urlparse(url).netloc.lower()

    if len(domain) > 25:
        return True

    if domain.count('.') > 3:
        return True

    if any(char.isdigit() for char in domain) and len(domain) > 15:
        return True

    return False


# 🔍 EXPLANATION ENGINE
def explain(url):
    reasons = []

    if "login" in url.lower():
        reasons.append("Contains login keyword")

    if "verify" in url.lower():
        reasons.append("Contains verification keyword")

    if "secure" in url.lower():
        reasons.append("Uses misleading 'secure' term")

    if url.startswith("http://"):
        reasons.append("Not using HTTPS")

    if "@" in url:
        reasons.append("Contains @ symbol (redirect trick)")

    if len(url) > 75:
        reasons.append("URL is too long")

    if not reasons:
        reasons.append("No obvious phishing patterns")

    return reasons


# 🏠 HOME
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "Backend Running 🚀",
        "message": "Use POST /predict"
    })


# 🚀 MAIN PREDICT API
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # 🔹 Extract features
        features = extract_features(url)

        # 🔹 ML prediction
        prediction = model.predict([features])[0]
        probs = model.predict_proba([features])[0]

        phishing_index = list(model.classes_).index(1)
        prob = probs[phishing_index]

        # 🔹 Extra checks
        google_flag = check_google_safe_browsing(url)
        brand_flag = detect_brand_phishing(url)
        suspicious_flag = detect_suspicious_domain(url)

        # 🔥 FINAL DECISION ENGINE (FIXED)
        if google_flag:
            result = "Phishing"
        elif brand_flag:
            result = "Phishing"
        elif suspicious_flag:
            result = "Phishing"
        elif prob > 0.6:
            result = "Phishing"
        else:
            result = "Safe"

        # 🔥 RISK SCORE
        risk = round(prob * 100)

        if google_flag:
            risk = max(risk, 90)

        if brand_flag:
            risk = max(risk, 80)

        if suspicious_flag:
            risk = max(risk, 70)

        if result == "Phishing":
            risk = max(risk, 70)

        # 🔥 CONFIDENCE FIX
        confidence = max(prob * 100, 5)

        # 🔍 EXPLANATION
        reasons = explain(url)

        return jsonify({
            "result": result,
            "confidence": round(confidence, 2),
            "risk_score": risk,
            "google_flag": google_flag,
            "brand_flag": brand_flag,
            "suspicious_flag": suspicious_flag,
            "reasons": reasons
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 🚀 RUN
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

from flask import Flask, request, jsonify
import joblib
from feature_extraction import extract_features
from flask_cors import CORS
import requests
import os

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

    except:
        return False


# 🔥 MAIN PREDICT API (FIXED LOGIC)
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
        prob = probs[phishing_index]  # 0 to 1

        # 3️⃣ Google Safe Browsing
        google_flag = check_google_safe_browsing(url)

        # 🔥 4️⃣ SMART DECISION LOGIC (FIXED)
        if google_flag:
            final_result = "Phishing"
        elif prob > 0.7:
            final_result = "Phishing"
        else:
            final_result = "Safe"

        # 🔥 5️⃣ REALISTIC RISK SCORE
        risk_score = round(prob * 100)

        return jsonify({
            "result": final_result,
            "confidence": round(prob * 100, 2),
            "risk_score": risk_score,
            "google_flag": google_flag
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Run locally
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

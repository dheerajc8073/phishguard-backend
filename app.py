from flask import Flask, request, jsonify
import joblib
from feature_extraction import extract_features
from flask_cors import CORS
import requests

GOOGLE_API_KEY = "AIzaSyDki5_jgsFkxrLhUyJu8nvROAXw2tS4vB8"


def check_google_safe_browsing(url):
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

    response = requests.post(api_url, json=payload)

    if response.status_code == 200 and response.json():
        return True  # Threat found
    return False


app = Flask(__name__)
CORS(app)

model = joblib.load("model.pkl")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data["url"]

    # 1️⃣ Extract features
    features = extract_features(url)

    # 2️⃣ ML prediction
    prediction = model.predict([features])[0]
    probs = model.predict_proba([features])[0]

    phishing_index = list(model.classes_).index(1)
    prob = probs[phishing_index]

    # 3️⃣ Google Safe Browsing check 🔥
    google_flag = check_google_safe_browsing(url)

    # 4️⃣ Final decision (HYBRID LOGIC)
    final_result = "Phishing" if (prediction == 1 or google_flag) else "Safe"

    return jsonify({
        "result": final_result,
        "confidence": round(prob * 100, 2),
        "google_flag": google_flag   # extra info
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

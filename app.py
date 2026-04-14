from flask import Flask, request, jsonify
import joblib
from feature_extraction import extract_features
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

model = joblib.load("model.pkl")


@app.route("/")
def home():
    return "PhishGuard Backend Running 🚀"


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data["url"]

    features = extract_features(url)

    prediction = model.predict([features])[0]
    prob = model.predict_proba([features])[0][1]

    return jsonify({
        "result": "Phishing" if prediction == 1 else "Safe",
        "confidence": round(prob * 100, 2)
    })


# IMPORTANT for deployment
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

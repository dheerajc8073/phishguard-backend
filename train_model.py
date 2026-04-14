import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from xgboost import XGBClassifier
import joblib
from feature_extraction import extract_features

# Load dataset
data = pd.read_csv("phishing.csv")
data.columns = data.columns.str.strip().str.lower()

urls = data["url"]
labels = data["label"]

# Features
X = urls.apply(extract_features).tolist()
y = labels

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# 🔥 XGBoost Model
model = XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss"
)

model.fit(X_train, y_train)

# Evaluate
print("Accuracy:", model.score(X_test, y_test))
print(classification_report(y_test, model.predict(X_test)))

# Save model
joblib.dump(model, "model.pkl")
print("✅ Model saved")

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
from feature_extraction import extract_features

# Load
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

# 🔥 BETTER MODEL (LESS OVERFIT)
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_split=5,
    min_samples_leaf=3,
    class_weight="balanced",
    random_state=42
)

model.fit(X_train, y_train)

print("Accuracy:", model.score(X_test, y_test))
print(classification_report(y_test, model.predict(X_test)))

joblib.dump(model, "model.pkl")
print("✅ Model saved")

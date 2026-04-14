import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
from feature_extraction import extract_features

# Load dataset
data = pd.read_csv("phishing.csv")
# Clean column names (VERY IMPORTANT)
data.columns = data.columns.str.strip().str.lower()

print(data.columns)  # check

urls = data["url"]
labels = data["label"]

# Convert URLs → features
X = urls.apply(extract_features).tolist()
y = labels

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Train model
model = RandomForestClassifier()
model.fit(X_train, y_train)

print("Accuracy:", model.score(X_test, y_test))

# Save model
joblib.dump(model, "model.pkl")

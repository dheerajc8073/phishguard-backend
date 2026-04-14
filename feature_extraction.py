from urllib.parse import urlparse

def extract_features(url):
    features = []

    features.append(len(url))  # URL length
    features.append(url.count('.'))  # dots
    features.append(1 if "https" in url else 0)
    features.append(1 if "@" in url else 0)
    features.append(1 if "-" in url else 0)

    domain = urlparse(url).netloc
    features.append(domain.count('.'))

   suspicious_words = [
    "login", "secure", "bank", "verify",
    "account", "update", "free", "bonus",
    "signin", "confirm", "password"
]
    features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)

    return features

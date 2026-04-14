from urllib.parse import urlparse

def extract_features(url):
    features = []

    # Basic features
    features.append(len(url))  # URL length
    features.append(url.count('.'))  # Number of dots
    features.append(1 if "https" in url else 0)
    features.append(1 if "@" in url else 0)
    features.append(1 if "-" in url else 0)

    # Domain-based feature
    domain = urlparse(url).netloc
    features.append(domain.count('.'))

    # Suspicious keywords
    suspicious_words = [
        "login", "secure", "bank", "verify",
        "account", "update", "free", "bonus",
        "signin", "confirm", "password"
    ]

    features.append(
        1 if any(word in url.lower() for word in suspicious_words) else 0
    )

    return features

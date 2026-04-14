from urllib.parse import urlparse

def extract_features(url):
    features = []

features.append(len(url))
features.append(url.count('.'))
features.append("https" in url)
features.append(url.count("//"))
features.append(url.count("="))
features.append(len(urlparse(url).path))
features.append(1 if url.startswith("http://") else 0)

    domain = urlparse(url).netloc
    features.append(domain.count('.'))

   suspicious_words = [
    "login", "secure", "bank", "verify",
    "account", "update", "free", "bonus",
    "signin", "confirm", "password"
]
    features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)

    return features

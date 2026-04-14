from urllib.parse import urlparse
import re


def extract_features(url):
    features = []

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    # 1–5 Basic
    features.append(len(url))
    features.append(url.count('.'))
    features.append(1 if parsed.scheme == "https" else 0)
    features.append(1 if "@" in url else 0)
    features.append(1 if "-" in domain else 0)

    # 6–10 Domain & path
    features.append(len(domain))
    features.append(len(path))
    features.append(domain.count('.'))
    features.append(url.count('/'))
    features.append(url.count('='))

    # 11–15 Special characters
    features.append(url.count('?'))
    features.append(url.count('%'))
    features.append(url.count('&'))
    features.append(url.count('!'))
    features.append(url.count('_'))

    # 16–20 Suspicious words
    suspicious_words = [
        "login", "secure", "bank", "verify", "account",
        "update", "free", "bonus", "signin", "confirm",
        "password", "click", "urgent", "limited", "offer"
    ]
    features.append(sum(word in url.lower() for word in suspicious_words))

    # 21–25 URL structure
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)  # IP
    features.append(1 if url.startswith("http://") else 0)
    features.append(1 if len(domain) > 20 else 0)
    features.append(1 if url.count('//') > 1 else 0)
    features.append(1 if '-' in domain else 0)

    # 26–30 More patterns
    features.append(len(re.findall(r'\d', url)))  # digits count
    features.append(len(re.findall(r'[A-Z]', url)))  # uppercase
    features.append(1 if "https" in domain else 0)
    features.append(1 if path.endswith(".exe") else 0)
    features.append(1 if "@" in domain else 0)

    # 31–35 Advanced heuristics
    features.append(1 if len(url) > 75 else 0)
    features.append(1 if domain.count('.') > 3 else 0)
    features.append(1 if "login" in path else 0)
    features.append(1 if "secure" in path else 0)
    features.append(1 if "update" in path else 0)

    return features

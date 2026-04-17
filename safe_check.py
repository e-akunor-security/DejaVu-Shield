# Simple Safe Link Checker (Version 8)

from datetime import datetime

BLOCKED_DOMAINS = [
    "malicious.com",
    "phishing-site.com",
    "badsite.net"
]

OFFICIAL_BRANDS = {
    "google": "google.com",
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "bank": "bank.com"
}

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "signin",
    "confirm",
    "reset"
]

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly"
]

def extract_domain(url):
    if "://" in url:
        url = url.split("://")[1]
    return url.split("/")[0].lower()

def is_official_domain(domain, official_domain):
    return domain == official_domain or domain.endswith("." + official_domain)

def is_ip_address(domain):
    parts = domain.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
    return True

def check_url(url):
    domain = extract_domain(url)

    # Detect URL shorteners
    if domain in URL_SHORTENERS:
        return "suspicious", "uses URL shortener"

    # Detect IP-based URLs
    if is_ip_address(domain):
        return "suspicious", "uses raw IP address"

    # Known malicious domains
    for bad_domain in BLOCKED_DOMAINS:
        if domain == bad_domain or domain.endswith("." + bad_domain):
            return "malicious", "matched blocked domain"

    # Suspicious patterns
    if "@" in url:
        return "suspicious", "contains @ symbol"

    if len(domain.split(".")) > 3:
        return "suspicious", "too many subdomains"

    # Brand + phishing keywords but not official domain
    for brand, official_domain in OFFICIAL_BRANDS.items():
        if brand in domain:
            for word in SUSPICIOUS_WORDS:
                if word in domain:
                    if not is_official_domain(domain, official_domain):
                        return "suspicious", "brand name with phishing keywords on non-official domain"

    return "safe", "no suspicious pattern found"

def log_result(url, result, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("log.txt", "a") as file:
        file.write(f"{timestamp} | {url} | {result} | {reason}\n")

def main():
    url = input("Enter a URL to check: ")

    result, reason = check_url(url)

    log_result(url, result, reason)

    print("\nResult:", result.upper())
    print("Reason:", reason)

    if result == "malicious":
        print("❌ This link is dangerous. Do NOT open it.")
    elif result == "suspicious":
        print("⚠️ This link looks suspicious. Be careful.")
    else:
        print("✅ This link appears safe.")

if __name__ == "__main__":
    main()

# 🛡️ DejaVu Shield (Beta v1.0)

DejaVu Shield is a lightweight cybersecurity tool designed to analyze URLs and detect potentially malicious or suspicious links.

## 🔍 Features

* Local threat detection:

  * Phishing-style domains
  * Suspicious keywords
  * URL shorteners
  * Raw IP addresses
  * “@” redirection trick

* External threat intelligence:

  * Integration with URLhaus API

* Risk scoring system:

  * Assigns a score (0–100) based on risk level

* Logging system:

  * Records all analyzed URLs
  * View logs inside the application

* User-friendly GUI:

  * Built with Tkinter
  * Clean and simple interface

## ⚠️ Status

This is a **Beta version** and is intended for testing and learning purposes.

## ▶️ How to Run

### Option 1 (Recommended)

Run the packaged application:

```
./DejaVuShield
```

### Option 2 (Developer Mode)

```
python app.py
```

## 🧠 How It Works

DejaVu Shield uses a layered approach:

1. Fast local checks (pattern-based detection)
2. External intelligence lookup (URLhaus)
3. Risk scoring and classification

## 📌 Disclaimer

This tool is for educational and testing purposes only.
It does not guarantee complete protection against all threats.

## 👨‍💻 Author

Developed by Emmanuel

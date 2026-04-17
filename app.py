import tkinter as tk
from datetime import datetime
import requests

# -----------------------------
# DATA
# -----------------------------

BLOCKED_DOMAINS = ["malicious.com", "badsite.net"]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co"]

OFFICIAL_BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com"
}

SUSPICIOUS_WORDS = ["login", "secure", "update", "verify"]

# -----------------------------
# HELPER FUNCTIONS
# -----------------------------

def extract_domain(url):
    if "://" in url:
        url = url.split("://")[1]
    return url.split("/")[0].lower()

def is_ip_address(domain):
    parts = domain.split(".")
    return all(p.isdigit() for p in parts) and len(parts) == 4

def is_official_domain(domain, official):
    return domain == official or domain.endswith("." + official)

# -----------------------------
# URLHAUS CHECK
# -----------------------------

def check_urlhaus(url):
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=3   # shorter timeout = faster app
        )
        data = response.json()

        if data.get("query_status") == "ok":
            return True, "found in URLhaus"
    except:
        pass

    return False, ""

# -----------------------------
# MAIN LOGIC (FAST FIRST)
# -----------------------------

def check_url(url):
    domain = extract_domain(url)

    # FAST CHECKS FIRST ⚡

    if "@" in url:
        return "suspicious", "contains @ symbol", "Local Detection", 55

    if domain in URL_SHORTENERS:
        return "suspicious", "uses URL shortener", "Local Detection", 60

    if is_ip_address(domain):
        return "suspicious", "uses raw IP address", "Local Detection", 65

    if len(domain.split(".")) > 3:
        return "suspicious", "too many subdomains", "Local Detection", 50

    for bad in BLOCKED_DOMAINS:
        if domain == bad or domain.endswith("." + bad):
            return "malicious", "matched blocked domain", "Local Detection", 90

    # PHISHING PATTERN
    for brand, official in OFFICIAL_BRANDS.items():
        if brand in domain:
            for word in SUSPICIOUS_WORDS:
                if word in domain:
                    if not is_official_domain(domain, official):
                        return "suspicious", "phishing-style domain", "Local Detection", 75

    # EXTERNAL CHECK LAST 🌐
    found, reason = check_urlhaus(url)

    if found:
        return "malicious", reason, "External Intelligence", 95

    return "safe", "no suspicious pattern found", "Local Detection", 10

# -----------------------------
# LOGGING
# -----------------------------

def log_result(url, result, reason):
    with open("log.txt", "a") as f:
        f.write(f"{datetime.now()} | {url} | {result} | {reason}\n")

# -----------------------------
# GUI FUNCTIONS
# -----------------------------

def run_check():
    url = entry.get().strip()

    if not url:
        result_label.config(text="Result: ERROR", fg="red")
        reason_label.config(text="Reason: Enter a URL")
        source_label.config(text="Source: ")
        score_label.config(text="Risk Score: ")
        return

    # Loading
    result_label.config(text="Result: CHECKING...", fg="blue")
    root.update()

    result, reason, source, score = check_url(url)

    log_result(url, result, reason)

    result_label.config(text="Result: " + result.upper())

    if result == "malicious":
        result_label.config(fg="red")
    elif result == "suspicious":
        result_label.config(fg="orange")
    else:
        result_label.config(fg="green")

    reason_label.config(text="Reason: " + reason)
    source_label.config(text="Source: " + source)
    score_label.config(text="Risk Score: " + str(score))

def clear_fields():
    entry.delete(0, tk.END)
    result_label.config(text="Result: ")
    reason_label.config(text="Reason: ")
    source_label.config(text="Source: ")
    score_label.config(text="Risk Score: ")

def show_about():
    about_window = tk.Toplevel(root)
    about_window.title("About DejaVu Shield")
    about_window.geometry("300x200")

    tk.Label(about_window, text="DejaVu Shield", font=("Arial", 14, "bold")).pack(pady=10)
    tk.Label(about_window, text="Version 1.0 (Beta)").pack(pady=5)
    tk.Label(about_window, text="A personal security tool\nfor analyzing suspicious links.").pack(pady=5)
 
def view_logs():
    log_window = tk.Toplevel(root)
    log_window.title("Log History")
    log_window.geometry("700x500")

    text_area = tk.Text(log_window, wrap="word")
    text_area.pack(expand=True, fill="both")

    try:
        with open("log.txt", "r") as file:
            for line in file:
                if "malicious" in line:
                    text_area.insert(tk.END, line, "malicious")
                elif "suspicious" in line:
                    text_area.insert(tk.END, line, "suspicious")
                else:
                    text_area.insert(tk.END, line)

        # Colors
        text_area.tag_config("malicious", foreground="red")
        text_area.tag_config("suspicious", foreground="orange")

    except FileNotFoundError:
        text_area.insert(tk.END, "No logs found.")

# -----------------------------
# GUI LAYOUT (IMPROVED)
# -----------------------------

import sys
import os
from tkinter import PhotoImage

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


root = tk.Tk()

icon_path = resource_path("shield.png")
icon = PhotoImage(file=icon_path)
root.iconphoto(True, icon)

root.title("DejaVu Shield")
root.geometry("600x650")

# Title
tk.Label(root, text="DejaVu Shield", font=("Arial", 16, "bold")).pack(pady=10)

# Input label
tk.Label(root, text="Enter URL:", font=("Arial", 12)).pack()

# Input field (bigger)
entry = tk.Entry(root, width=70, font=("Arial", 11))
entry.pack(pady=10)

# Buttons (bigger)
tk.Button(root, text="Check", command=run_check, width=20, height=2).pack(pady=5)
tk.Button(root, text="Clear", command=clear_fields, width=20, height=2).pack(pady=5)
tk.Button(root, text="View Logs", command=view_logs, width=20, height=2).pack(pady=5)
tk.Button(root, text="About", command=show_about, width=20, height=2).pack(pady=5)

# Result
result_label = tk.Label(root, text="Result: ", font=("Arial", 12, "bold"))
result_label.pack(pady=10)

# Reason
reason_label = tk.Label(root, text="Reason: ", font=("Arial", 11))
reason_label.pack(pady=5)

# Source
source_label = tk.Label(root, text="Source: ", font=("Arial", 11))
source_label.pack(pady=5)

# Risk Score
score_label = tk.Label(root, text="Risk Score: ", font=("Arial", 11, "bold"))
score_label.pack(pady=10)

root.mainloop()

import tkinter as tk
from tkinter import ttk
from datetime import datetime
import requests
import hashlib
import os
from tkinter import filedialog

VT_API_KEY = "7f4f4e499d2905e46057be07259ecf927f054c25629339e6a856471e8128e18c"

# -----------------------------
# DATA
# -----------------------------

BLOCKED_DOMAINS = ["malicious.com", "badsite.net"]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co"]

SUSPICIOUS_TLDS = [".zip", ".top", ".xyz", ".ru", ".click", ".gq", ".tk"]

OFFICIAL_BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com"
}

SUSPICIOUS_WORDS = ["login", "secure", "update", "verify"]

# -----------------------------
# SESSION STATISTICS
# -----------------------------

session_stats = {
    "total": 0,
    "safe": 0,
    "suspicious": 0,
    "malicious": 0,
    "unknown": 0
}

# -----------------------------
# HELPER FUNCTIONS
# -----------------------------

def update_session_stats(result):
    session_stats["total"] += 1

    if result in session_stats:
        session_stats[result] += 1

def refresh_statistics_dashboard():
    total_stats_label.config(
        text=f"Total Scans: {session_stats['total']}"
    )

    safe_stats_label.config(
        text=f"Safe: {session_stats['safe']}"
    )

    suspicious_stats_label.config(
        text=f"Suspicious: {session_stats['suspicious']}"
    )

    malicious_stats_label.config(
        text=f"Malicious: {session_stats['malicious']}"
    )

    unknown_stats_label.config(
        text=f"Unknown: {session_stats['unknown']}"
    )

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

def check_virustotal(url):
    try:
        headers = {
            "x-apikey": VT_API_KEY
        }

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=5
        )

        if response.status_code != 200:
            return False, "VirusTotal unavailable", "unknown", 0

        data = response.json()
        analysis_id = data["data"]["id"]

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=5
        )

        if report.status_code != 200:
            return False, "VirusTotal report unavailable", "unknown", 0

        report_data = report.json()
        stats = report_data["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        total_flags = malicious + suspicious

        # ✅ NEW: classification
        if total_flags == 0:
            status = "safe"
            score = 10
        elif total_flags <= 2:
            status = "suspicious"
            score = 45
        elif total_flags <= 5:
            status = "suspicious"
            score = 70
        elif total_flags <= 10:
            status = "malicious"
            score = 88
        else:
            status = "malicious"
            score = 98

        return True, f"{total_flags} vendors flagged this URL", status, score

    except Exception:
        return False, "VirusTotal error", "unknown", 0


# -----------------------------
# MAIN LOGIC (FAST FIRST)
# -----------------------------

def check_url(url):
    domain = extract_domain(url)
    # Suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return "suspicious", "uses suspicious top-level domain", "Local Detection", 68

    # Punycode trick
    if "xn--" in domain:
        return "suspicious", "contains punycode / lookalike domain", "Local Detection", 78

    # Fake secure wording
    fake_words = ["secure", "verify", "update", "login", "account"]

    for word in fake_words:
        if word in domain and not domain.endswith(".com"):
            return "suspicious", "contains phishing-style trust wording", "Local Detection", 72

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

    def check_url(url):
        domain = extract_domain(url)

    # FAST LOCAL CHECKS FIRST

    if "@" in url:
        return "suspicious", "contains @ symbol", "Local Detection", 55

    if domain in URL_SHORTENERS:
        return "suspicious", "uses URL shortener", "Local Detection", 60

    if is_ip_address(domain):
        return "suspicious", "uses raw IP address", "Local Detection", 65

    if len(domain.split(".")) > 3:
        return "suspicious", "too many subdomains", "Local Detection", 50

    for bad_domain in BLOCKED_DOMAINS:
        if domain == bad_domain or domain.endswith("." + bad_domain):
            return "malicious", "matched blocked domain", "Local Detection", 90

    # phishing-style checks
    for brand, official in OFFICIAL_BRANDS.items():
        if brand in domain:
            for word in SUSPICIOUS_WORDS:
                if word in domain:
                    if not is_official_domain(domain, official):
                        return "suspicious", "phishing-style domain", "Local Detection", 75

    # -----------------------------
    # External Intelligence - URLhaus
    # -----------------------------
    found, reason = check_urlhaus(url)

    if found:
        return "malicious", reason, "URLhaus", 95

 # -----------------------------
# External Intelligence - VirusTotal
# -----------------------------
    vt_found, vt_reason, vt_status, vt_score = check_virustotal(url)

    if vt_found:
        return vt_status, vt_reason, "VirusTotal", vt_score

    # -----------------------------
    # Final Safe
    # -----------------------------
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
        update_session_stats("malicious")

    elif result == "suspicious":
          result_label.config(fg="orange")
          update_session_stats("suspicious")

    else:
          result_label.config(fg="green")
          update_session_stats("safe")

    refresh_statistics_dashboard()

    reason_label.config(text="Reason: " + reason)
    source_label.config(text="Source: " + source)

    score_label.config(text="Risk Score: " + str(score))
    risk_bar["value"] = score

    if score <= 30:
        score_label.config(fg="green")

    elif score <= 69:
        score_label.config(fg="orange")

    else:
        score_label.config(fg="red")

    history_list.insert(0, url + " - " + result.upper())

    if history_list.size() > 5:
        history_list.delete(5)

def clear_fields():
    entry.delete(0, tk.END)
    result_label.config(text="Result: ")
    reason_label.config(text="Reason: ")
    source_label.config(text="Source: ")
    score_label.config(text="Risk Score: ")
    risk_bar["value"] = 0

def show_about():
    about_window = tk.Toplevel(root)
    about_window.title("About DejaVu Shield")
    about_window.geometry("300x200")

    tk.Label(about_window, text="DejaVu Shield", font=("Arial", 14, "bold")).pack(pady=10)
    tk.Label(about_window, text="Version 1.0 (Beta)").pack(pady=5)
    tk.Label(about_window, text="A personal security tool\nfor analyzing suspicious links.").pack(pady=5)

def export_report():
    with open("report.txt", "w") as file:
        file.write("DejaVu Shield Report\n")
        file.write("====================\n\n")

        for i in range(history_list.size()):
            file.write(history_list.get(i) + "\n")

def export_csv():
    with open("report.csv", "w") as file:
        file.write("URL,Result\n")

        for i in range(history_list.size()):
            item = history_list.get(i)

            if " - " in item:
                parts = item.split(" - ", 1)
                url = parts[0]
                result = parts[1]
                file.write(url + "," + result + "\n")
 
def view_logs():
    log_window = tk.Toplevel(root)
    log_window.title("Log History")
    log_window.geometry("700x500")

    text_area = tk.Text(log_window, wrap="word")
    text_area.pack(expand=True, fill="both")

    try:
        with open("log.txt", "r") as file:
            for line in file:
                lower_line = line.lower()

                if "malicious" in lower_line:
                    text_area.insert(tk.END, line, "malicious")

                elif "suspicious" in lower_line:
                    text_area.insert(tk.END, line, "suspicious")

                elif "safe" in lower_line:
                    text_area.insert(tk.END, line, "safe")

                else:
                    text_area.insert(tk.END, line)

        text_area.tag_config("malicious", foreground="red")
        text_area.tag_config("suspicious", foreground="orange")
        text_area.tag_config("safe", foreground="green")

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

def calculate_file_hash(filepath):
    sha256 = hashlib.sha256()

    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except Exception as e:
        return f"Error: {e}"

def check_file_hash_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            total_engines = malicious + suspicious + harmless

            if malicious > 0:
                verdict = "🚨 MALICIOUS"
                color = "red"

            elif suspicious > 0:
                verdict = "⚠ SUSPICIOUS"
                color = "yellow"

            else:
                verdict = "✅ SAFE"
                color = "lightgreen"

            return (
                f"{verdict}\n\n"
                f"VirusTotal Results\n\n"
                f"Malicious: {malicious}\n"
                f"Suspicious: {suspicious}\n"
                f"Harmless: {harmless}\n\n"
                f"{malicious + suspicious} / {total_engines} vendors flagged this file"
            )   
                
        elif response.status_code == 404:
            return (
                "❓ UNKNOWN FILE\n\n"
                "This file hash was not found in the VirusTotal database.\n"
                "This does not mean the file is safe or malicious.\n\n"
                "Recommendation:\n"
                "Only run this file if you trust its source."
            )
          

        else:
            return f"VirusTotal Error: {response.status_code}"

    except Exception as e:
        return f"Error: {e}"

def scan_file():
    filepath = filedialog.askopenfilename()

    if not filepath:
        return

    filename = os.path.basename(filepath)

    result_label.config(text="Calculating file hash...")

    file_hash = calculate_file_hash(filepath)

    if file_hash.startswith("Error"):
        result_label.config(text=file_hash)
        return

    result_label.config(
        text=f"SHA256:\n{file_hash}\n\nChecking VirusTotal..."
    )

    vt_result = check_file_hash_virustotal(file_hash) 

    if "MALICIOUS" in vt_result:
        history_list.insert(0, f"[FILE] {filename} - MALICIOUS")
        update_session_stats("malicious")

    elif "SUSPICIOUS" in vt_result:
        history_list.insert(0, f"[FILE] {filename} - SUSPICIOUS")
        update_session_stats("suspicious")

    elif "UNKNOWN FILE" in vt_result:
        history_list.insert(0, f"[FILE] {filename} - UNKNOWN")
        update_session_stats("unknown")

    elif "SAFE" in vt_result:
        history_list.insert(0, f"[FILE] {filename} - SAFE")
        update_session_stats("safe")

    else:
        history_list.insert(0, f"[FILE] {filename} - UNKNOWN")
        update_session_stats("unknown")

    refresh_statistics_dashboard()

    if "MALICIOUS" in vt_result:
        result_label.config(
            text=f"File: {filename}\n\nSHA256:\n{file_hash}\n\n{vt_result}",
            fg="red"
        )

    elif "SUSPICIOUS" in vt_result:
        result_label.config(
            text=f"File: {filename}\n\nSHA256:\n{file_hash}\n\n{vt_result}",
            fg="yellow"
        )

    elif "UNKNOWN FILE" in vt_result:
        result_label.config(
            text=f"File: {filename}\n\nSHA256:\n{file_hash}\n\n{vt_result}",
            fg="orange"
        )

    else:
        result_label.config(
            text=f"File: {filename}\n\nSHA256:\n{file_hash}\n\n{vt_result}",
            fg="lightgreen"
        )

root = tk.Tk()

icon_path = resource_path("shield.png")
icon = PhotoImage(file=icon_path)
root.iconphoto(True, icon)

root.title("DejaVu Shield")
root.geometry("720x980")
root.configure(bg="#1e1e1e")

# Title
tk.Label(root, text="DejaVu Shield", font=("Arial", 16, "bold")).pack(pady=10)

# -----------------------------
# SESSION STATISTICS DASHBOARD
# -----------------------------

stats_frame = tk.Frame(
    root,
    bg="#252525",
    bd=1,
    relief="solid"
)
stats_frame.pack(fill="x", padx=20, pady=(0, 10))

# Dashboard logo
dashboard_logo = PhotoImage(
    file=resource_path("shield.png")
).subsample(6, 6)

dashboard_logo_label = tk.Label(
    stats_frame,
    image=dashboard_logo,
    bg="#252525"
)
dashboard_logo_label.grid(
    row=0,
    column=0,
    rowspan=3,
    padx=12,
    pady=8
)

# Dashboard heading
tk.Label(
    stats_frame,
    text="Session Statistics",
    font=("Arial", 12, "bold"),
    bg="#252525",
    fg="white"
).grid(
    row=0,
    column=1,
    columnspan=5,
    pady=(8, 4)
)

# Statistics labels
total_stats_label = tk.Label(
    stats_frame,
    text="Total Scans: 0",
    bg="#252525",
    fg="white"
)
total_stats_label.grid(row=1, column=1, padx=8, pady=4)

safe_stats_label = tk.Label(
    stats_frame,
    text="Safe: 0",
    bg="#252525",
    fg="lightgreen"
)
safe_stats_label.grid(row=1, column=2, padx=8, pady=4)

suspicious_stats_label = tk.Label(
    stats_frame,
    text="Suspicious: 0",
    bg="#252525",
    fg="yellow"
)
suspicious_stats_label.grid(row=1, column=3, padx=8, pady=4)

malicious_stats_label = tk.Label(
    stats_frame,
    text="Malicious: 0",
    bg="#252525",
    fg="red"
)
malicious_stats_label.grid(row=2, column=1, padx=8, pady=(4, 8))

unknown_stats_label = tk.Label(
    stats_frame,
    text="Unknown: 0",
    bg="#252525",
    fg="orange"
)
unknown_stats_label.grid(row=2, column=2, padx=8, pady=(4, 8))

refresh_statistics_dashboard()

# Input label
tk.Label(root, text="Enter URL:", font=("Arial", 12)).pack()

# Input field (bigger)
entry = tk.Entry(root, width=50, bg="#2d2d2d", fg="white", insertbackground="white")
entry.pack(pady=10)

# Buttons (bigger)
button_frame = tk.Frame(root, bg="#1e1e1e")
button_frame.pack(pady=8)

tk.Button(button_frame, text="Check", command=run_check, width=12, bg="#333333", fg="white").grid(row=0, column=0, padx=3, pady=3)

tk.Button(button_frame, text="Clear", command=clear_fields, width=12, bg="#333333", fg="white").grid(row=0, column=1, padx=3, pady=3)

tk.Button(button_frame, text="Logs", command=view_logs, width=12, bg="#333333", fg="white").grid(row=0, column=2, padx=3, pady=3)

tk.Button(button_frame, text="About", command=show_about, width=12, bg="#333333", fg="white").grid(row=1, column=0, padx=3, pady=3)

tk.Button(button_frame, text="TXT", command=export_report, width=12, bg="#333333", fg="white").grid(row=1, column=1, padx=3, pady=3)

tk.Button(button_frame, text="CSV", command=export_csv, width=12, bg="#333333", fg="white").grid(row=1, column=2, padx=3, pady=3)

tk.Button(
    button_frame,
    text="Scan File",
    command=scan_file,
    width=12,
    bg="#333333",
    fg="white"
).grid(row=0, column=6, padx=5)

# Result
result_label = tk.Label(root, text="Result: ", bg="#1e1e1e", fg="white")
result_label.pack(pady=4)

# Reason
reason_label = tk.Label(root, text="Reason: ", bg="#1e1e1e", fg="white")
reason_label.pack(pady=5)

# Source
source_label = tk.Label(root, text="Source: ", bg="#1e1e1e", fg="white")
source_label.pack(pady=5)

# Risk Score
score_label = tk.Label(root, text="Risk Score: ", bg="#1e1e1e", fg="white")
score_label.pack(pady=3)

risk_bar = ttk.Progressbar(root, length=300, mode="determinate", maximum=100)
risk_bar.pack(pady=3)

tk.Label(root, text="Recent Scans", bg="#1e1e1e", fg="white").pack(pady=(3, 0))


history_list = tk.Listbox(
    root,
    width=55,
    height=8,
    bg="#2d2d2d",
    fg="white"
)
history_list.pack(pady=5, fill="x", padx=20)

root.mainloop()

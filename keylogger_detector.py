import psutil
import hashlib
import os
import time
import requests
from pathlib import Path

# =================== CONFIGURATION ====================
VT_API_KEY = ""  # Replace this with your actual key

SUSPICIOUS_NAMES = {
    "keylogger.exe", "klg.exe", "spyware.exe", "hooker.exe", "svch0st.exe"
}

SUSPICIOUS_FILES = {"keylog", "logkeys", "keystrokes"}

# =================== VIRUSTOTAL ====================
def vt_check_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_votes = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            if malicious_votes > 0:
                print(f"[🚨] VirusTotal: MALICIOUS - {file_hash} ({malicious_votes} engines)")
            else:
                print(f"[✅] VirusTotal: Clean - {file_hash}")
        elif response.status_code == 404:
            print(f"[❓] VirusTotal: Hash not found - {file_hash}")
        else:
            print(f"[⚠️] VirusTotal API error {response.status_code} for hash {file_hash}")
    except Exception as e:
        print(f"[❌] Error checking VirusTotal: {e}")

# =================== HASHING ====================
def compute_hash(file_path, algo="sha256"):
    try:
        h = hashlib.new(algo)
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# =================== PROCESS SCANNER ====================
def scan_processes():
    print("\n🔍 Scanning running processes...")
    scanned = 0
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info['name'].lower()
            exe = proc.info['exe']
            print(f"📌 Checking: {name} (PID {proc.pid})")

            if name in SUSPICIOUS_NAMES:
                print(f"[⚠️] Suspicious process name: {name} (PID {proc.pid})")

            if exe:
                hash_val = compute_hash(exe)
                if hash_val:
                    print(f"🔎 Hash: {hash_val}")
                    vt_check_hash(hash_val)
                    scanned += 1
                    time.sleep(15)  # To avoid exceeding VirusTotal free API limits
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    print(f"\n✅ Process scan complete. {scanned} files scanned via VirusTotal.")

# =================== FILE BEHAVIOR CHECK ====================
def check_file_behavior():
    print("\n📂 Checking for suspicious file activity...")
    suspicious = []
    home = str(Path.home())
    for root, dirs, files in os.walk(home):
        for file in files:
            if any(keyword in file.lower() for keyword in SUSPICIOUS_FILES):
                full_path = os.path.join(root, file)
                suspicious.append(full_path)
    if suspicious:
        for path in suspicious:
            print(f"[⚠️] Possible keylogger file: {path}")
    else:
        print("✅ No suspicious keylogger-related files found.")

# =================== NETWORK MONITOR ====================
def check_network_connections():
    print("\n🌐 Checking for suspicious outbound network connections...")
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
            ip = conn.raddr.ip
            port = conn.raddr.port
            pid = conn.pid
            proc_name = psutil.Process(pid).name() if pid else "Unknown"
            print(f"[📡] Connection: {proc_name} (PID {pid}) -> {ip}:{port}")

# =================== MAIN RUNNER ====================
def run_full_scan():
    print("🚀 Starting full keylogger detection scan...\n")
    scan_processes()
    check_file_behavior()
    check_network_connections()
    print("\n✅ Scan complete.")

if __name__ == "__main__":
    run_full_scan()

#!/usr/bin/env python3

import sys
import os
import subprocess
import hashlib
import zipfile
import magic
import yara

# ==============================
# CONFIG
# ==============================
YARA_RULES_FILE = "rules.yar"

# ==============================
# LOAD YARA RULES (ONCE)
# ==============================
try:
    YARA_RULES = yara.compile(filepath="/home/sudip-howlader/file-guard/rules.yar")
except Exception:
    YARA_RULES = None

# ==============================
# INPUT CHECK
# ==============================
if len(sys.argv) != 2:
    print("ERROR")
    sys.exit(1)

file_path = sys.argv[1]

if not os.path.exists(file_path):
    print("ERROR")
    sys.exit(1)


# ==============================
# FILE TYPE DETECTION
# ==============================
def detect_file_type(file_path):
    try:
        return magic.from_file(file_path, mime=True)
    except:
        return "unknown"


# ==============================
# CLAMAV SCAN
# ==============================
def clamav_scan(target):
    try:
        result = subprocess.run(
            ["clamscan", "-r", "--infected", target], capture_output=True, text=True
        )
        if "FOUND" in result.stdout:
            return "UNSAFE"
        return "SAFE"
    except:
        return "ERROR"


# ==============================
# YARA SCAN (IMPROVED)
# ==============================
def yara_scan(file_path):
    if not YARA_RULES:
        return "ERROR"

    try:
        matches = YARA_RULES.match(file_path)

        highest = "SAFE"

        for match in matches:
            severity = match.meta.get("severity", "low")

            if severity == "critical":
                return "UNSAFE"

            elif severity == "high":
                highest = "UNSAFE"

            elif severity == "medium" and highest != "UNSAFE":
                highest = "SUSPICIOUS"

        return highest

    except:
        return "ERROR"


# ==============================
# ARCHIVE SCAN
# ==============================
def scan_archive(file_path):
    temp_dir = "/tmp/fileguard_scan"

    try:
        if zipfile.is_zipfile(file_path):
            os.makedirs(temp_dir, exist_ok=True)

            with zipfile.ZipFile(file_path, "r") as z:
                z.extractall(temp_dir)

            return clamav_scan(temp_dir)

    except:
        return "ERROR"

    return "SAFE"


# ==============================
# HEURISTIC SCAN
# ==============================
def heuristic_scan(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

            patterns = [b"eval(", b"base64", b"/bin/bash", b"powershell", b"cmd.exe"]

            for p in patterns:
                if p in data:
                    return "UNSAFE"

    except:
        return "ERROR"

    return "SAFE"


# ==============================
# PROCESS SCAN (LIGHT EDR)
# ==============================
def process_scan():
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        output = result.stdout.lower()

        suspicious = ["nc -e", "bash -i", "powershell", "curl http", "wget http"]

        for s in suspicious:
            if s in output:
                return "UNSAFE"

        return "SAFE"

    except:
        return "ERROR"


# ==============================
# FILE STRUCTURE CHECK
# ==============================
def file_structure_check(file_path):
    try:
        result = subprocess.run(["file", file_path], capture_output=True, text=True)

        if "executable" in result.stdout.lower():
            return "UNSAFE"

        return "SAFE"

    except:
        return "ERROR"


# ==============================
# HASH (FOR FUTURE USE)
# ==============================
def get_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# ==============================
# MAIN SCAN ENGINE
# ==============================
def scan(file_path):

    # 1. Archive scan
    archive_result = scan_archive(file_path)
    if archive_result == "UNSAFE":
        return "UNSAFE"

    # 2. ClamAV
    clam_result = clamav_scan(file_path)
    if clam_result == "UNSAFE":
        return "UNSAFE"

    # 3. YARA
    yara_result = yara_scan(file_path)
    if yara_result == "UNSAFE":
        return "UNSAFE"
    elif yara_result == "SUSPICIOUS":
        return "SUSPICIOUS"

    # 4. Heuristic
    if heuristic_scan(file_path) == "UNSAFE":
        return "UNSAFE"

    # 5. Structure check
    if file_structure_check(file_path) == "UNSAFE":
        return "UNSAFE"

    # 6. Process scan
    if process_scan() == "UNSAFE":
        return "UNSAFE"

    # 7. Hash (optional use)
    _ = get_hash(file_path)

    return "SAFE"


# ==============================
# EXECUTE
# ==============================
try:
    print(scan(file_path))
except:
    print("ERROR")

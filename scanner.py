#!/usr/bin/env python3

import sys
import os
import subprocess
import hashlib
import zipfile
import magic
import yara
import tempfile
import shutil

# ==============================
# CONFIG
# ==============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
YARA_RULES_PATH = os.path.join(BASE_DIR, "rules.yar")

# ==============================
# LOAD YARA RULES
# ==============================
try:
    YARA_RULES = yara.compile(filepath=YARA_RULES_PATH)
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
    except Exception:
        return "unknown"

# ==============================
# SAFE ZIP EXTRACTION
# ==============================
def safe_extract(zip_ref, path):
    for member in zip_ref.namelist():
        member_path = os.path.join(path, member)
        if not os.path.realpath(member_path).startswith(os.path.realpath(path)):
            raise Exception("Zip Slip detected")
    zip_ref.extractall(path)

# ==============================
# CLAMAV SCAN
# ==============================
def clamav_scan(target):
    try:
        result = subprocess.run(
            ["clamscan", "-r", "--infected", target],
            # ["clamscan", "--no-summary", target],
            capture_output=True,
            text=True
        )
        if "FOUND" in result.stdout:
            return "UNSAFE"
        return "SAFE"
    except Exception:
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

    except Exception:
        return "ERROR"

# ==============================
# ARCHIVE SCAN
# ==============================
def scan_archive(file_path):
    temp_dir = tempfile.mkdtemp(prefix="fileguard_")

    try:
        if zipfile.is_zipfile(file_path):

            with zipfile.ZipFile(file_path, "r") as z:
                safe_extract(z, temp_dir)

            return clamav_scan(temp_dir)

    except Exception:
        return "ERROR"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return "SAFE"


# ==============================
# HEURISTIC SCAN
# ==============================
def heuristic_scan(file_path):
    try:
        with open(file_path, "rb") as f:
            # data = f.read()
            data = f.read(1024 * 1024)  # limit to 1MB

            patterns = [
                (b"eval(", "high"),
                (b"base64", "medium"),
                (b"/bin/bash", "medium"),
                (b"powershell", "high"),
                (b"cmd.exe", "high"),
            ]

            # for p in patterns:
            #     if p in data:
            #         return "UNSAFE"
            result = "SAFE"

            for pattern, severity in patterns:
                if pattern in data:
                    if severity == "high":
                        return "UNSAFE"
                    elif severity == "medium" and result != "UNSAFE":
                        result = "SUSPICIOUS"

            return result

    except Exception:
        return "ERROR"


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
                return "SUSPICIOUS"

        return "SAFE"

    except Exception:
        return "ERROR"


# ==============================
# FILE STRUCTURE CHECK
# ==============================
def file_structure_check(file_path):
    try:
        result = subprocess.run(["file", file_path], capture_output=True, text=True)

        if "executable" in result.stdout.lower():
            return "SUSPICIOUS"

        return "SAFE"

    except Exception:
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
    heuristic_result = heuristic_scan(file_path)
    if heuristic_result == "UNSAFE":
        return "UNSAFE"
    elif heuristic_result == "SUSPICIOUS":
        return "SUSPICIOUS"

    # 5. Structure check
    structure_result = file_structure_check(file_path)
    if structure_result == "SUSPICIOUS":
        return "SUSPICIOUS"

    # 6. Process scan
    process_result = process_scan()
    if process_result == "SUSPICIOUS":
        return "SUSPICIOUS"

    # 7. Hash (for future use)
    _ = get_hash(file_path)

    return "SAFE"


# ==============================
# EXECUTE
# ==============================
try:
    print(scan(file_path))
except Exception:
    print("ERROR")
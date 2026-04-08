#!/usr/bin/env python3

import sys
import os
import subprocess
import hashlib
import zipfile
import tempfile
import shutil
import magic  # python-magic
import yara


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
def detect_file_type(path):
    try:
        return magic.from_file(path, mime=True)
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
    """Return SAFE / UNSAFE / ERROR based on clamscan output."""
    try:
        result = subprocess.run(
            ["clamscan", "-r", "--infected", target],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if "FOUND" in result.stdout:
            return "UNSAFE"
        return "SAFE"
    except Exception:
        return "ERROR"


# ==============================
# YARA SCAN (IMPROVED)
# ==============================
def yara_scan(path):
    """Return SAFE / SUSPICIOUS / UNSAFE / ERROR based on YARA matches."""
    if not YARA_RULES:
        return "ERROR"

    try:
        matches = YARA_RULES.match(path)

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
def scan_archive(path):
    temp_dir = tempfile.mkdtemp(prefix="fileguard_")

    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, "r") as z:
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
def heuristic_scan(path):
    try:
        with open(path, "rb") as f:
            data = f.read(1024 * 1024)  # limit to 1MB

            patterns = [
                (b"eval(", "high"),
                (b"base64", "medium"),
                (b"/bin/bash", "medium"),
                (b"powershell", "high"),
                (b"cmd.exe", "high"),
            ]

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
def file_structure_check(path):
    try:
        result = subprocess.run(["file", path], capture_output=True, text=True)

        if "executable" in result.stdout.lower():
            return "SUSPICIOUS"

        return "SAFE"

    except Exception:
        return "ERROR"


# ==============================
# HASH (FOR FUTURE USE)
# ==============================
def get_hash(path):
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# ==============================
# MAIN SCAN ENGINE
# ==============================
def scan(path):
    # 1. Archive scan
    archive_result = scan_archive(path)
    if archive_result == "UNSAFE":
        return "UNSAFE"

    # 2. ClamAV
    clam_result = clamav_scan(path)
    if clam_result == "UNSAFE":
        return "UNSAFE"

    # 3. YARA
    yara_result = yara_scan(path)
    if yara_result == "UNSAFE":
        return "UNSAFE"
    elif yara_result == "SUSPICIOUS":
        return "SUSPICIOUS"

    # 4. Heuristic
    heuristic_result = heuristic_scan(path)
    if heuristic_result == "UNSAFE":
        return "UNSAFE"
    elif heuristic_result == "SUSPICIOUS":
        return "SUSPICIOUS"

    # 5. Structure check
    structure_result = file_structure_check(path)
    if structure_result == "SUSPICIOUS":
        return "SUSPICIOUS"

    # 6. Process scan
    process_result = process_scan()
    if process_result == "SUSPICIOUS":
        return "SUSPICIOUS"

    # 7. Hash (for future use)
    _ = get_hash(path)

    return "SAFE"


# ==============================
# EXECUTE
# ==============================
try:
    print(scan(file_path))
except Exception:
    print("ERROR")
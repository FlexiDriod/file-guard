#!/bin/bash

set -e
set -o pipefail
set -o nounset   # It prevents using undefined variables.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# ==================================================================================
# File Guard - Monitor Script
# ==================================================================================
# Requires: inotify-tools, libnotify-bin, zenity, pulseaudio-utils
# Command: sudo apt install inotify-tools libnotify-bin zenity pulseaudio-utils
# ===================================================================================

WATCH_DIR="/home/sudip-howlader/Downloads"
SCANNER_SCRIPT="/home/sudip-howlader/file-guard/scanner.py"
LOG_DIR="/home/sudip-howlader/file-guard/logs"
QUARANTINE_DIR="/home/sudip-howlader/file-guard/quarantine"

# 🔥 FIX 5: Safe scanner execution
safe_run() {
    "$@" || return 0
}

# Ensure log directory exists
if [ ! -d "$LOG_DIR" ]; then
    echo "Logs directory does NOT exist, creating it..."
    mkdir -p "$LOG_DIR"
    chmod 700 "$LOG_DIR"
fi

if [ ! -d "$QUARANTINE_DIR" ]; then
    echo "Quarantine directory does NOT exist, creating it..."
    mkdir -p "$QUARANTINE_DIR"
    chmod 700 "$QUARANTINE_DIR"
fi

# Unique log file with timestamp
LOG_FILE="$LOG_DIR/log_$(date +%Y-%m-%d_%H-%M-%S).log"

# ==============================
# Dedup file tracking (NEW)
# Prevent scanning same file multiple times
# ==============================
PROCESSED="/var/tmp/fileguard_seen"
touch "$PROCESSED"
chmod 600 "$PROCESSED"

# ==============================
# 🔐 Scanner Integrity Check (NEW)
# ==============================
SCANNER_HASH_EXPECTED="9f191892dd6bc8dd2b426cdcb2456e9b2b5ab4559be62de8123233be0cb832eb"

if [ ! -f "$SCANNER_SCRIPT" ]; then
    echo "Scanner script not found!" | tee -a "$LOG_FILE"
    exit 1
fi

SCANNER_HASH=$(sha256sum "$SCANNER_SCRIPT" | awk '{print $1}')
if [ "$SCANNER_HASH" != "$SCANNER_HASH_EXPECTED" ]; then
    echo "Scanner integrity FAILED!" | tee -a "$LOG_FILE"
    exit 1
fi


# SOUND FILES
SOUND_ALERT="/usr/share/sounds/freedesktop/stereo/dialog-warning.oga"
SOUND_DELETE="/usr/share/sounds/freedesktop/stereo/service-logout.oga"
SOUND_QUARANTINE="/usr/share/sounds/freedesktop/stereo/complete.oga"
SOUND_SAFE="/usr/share/sounds/freedesktop/stereo/message.oga"
SOUND_IGNORE="/usr/share/sounds/freedesktop/stereo/dialog-information.oga"

# Shutdown Handler
handle_shutdown() {
    echo "" | tee -a "$LOG_FILE"
    echo "$(date) - Service Stopping..." | tee -a "$LOG_FILE"
    echo "File Guard Stopped........" | tee -a "$LOG_FILE"
    pkill -P $$
    exit 0
}

# Trap system signals (shutdown/restart)
trap handle_shutdown SIGTERM SIGINT

# Start Message
echo "############################################" | tee -a "$LOG_FILE"
echo "File Guard Started......" | tee -a "$LOG_FILE"
echo "Monitoring: $WATCH_DIR" | tee -a "$LOG_FILE"
echo "Log File: $LOG_FILE" | tee -a "$LOG_FILE"
echo "###########################################" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

if [ ! -x "$(command -v python3)" ]; then
    echo "Python3 not found!" | tee -a "$LOG_FILE"
    exit 1
fi

# Monitor Function
monitor_download() {
    inotifywait -m -e close_write,create --format '%w %f' "$WATCH_DIR" 2>/dev/null | \
    while read -r path file; do

        # 🔥 FIX: Safe full path resolution
        FULL_PATH="$(realpath "$path$file" 2>/dev/null || true)"

        # 🔥 Extra: ensure file is inside WATCH_DIR (anti path escape)
        case "$FULL_PATH" in
            "$WATCH_DIR"/*) ;;
            *)
                echo "Skipped: path escape attempt" | tee -a "$LOG_FILE"
                continue
                ;;
        esac

        # 🔥 FIX: Validate file safety (prevents symlink attacks)
        if [ ! -f "$FULL_PATH" ] || [ -L "$FULL_PATH" ]; then
            echo "Skipped: unsafe file (missing or symlink)" | tee -a "$LOG_FILE"
            continue
        fi

        TIMESTAMP=$(date)

        # 🔥 FIX 2: Dedup check
        if ! grep -qxF "$FULL_PATH" "$PROCESSED"; then
            echo "$FULL_PATH" >> "$PROCESSED"
        else
            continue
        fi

        echo "" | tee -a "$LOG_FILE"
        echo "--------------------------------------------------" | tee -a "$LOG_FILE"
        echo "$TIMESTAMP - New file detected" | tee -a "$LOG_FILE"
        echo "File: $file" | tee -a "$LOG_FILE"
        echo "Path: $FULL_PATH" | tee -a "$LOG_FILE"

        # 🔥 FIX 3: Sanitize filename (log safety)
        SAFE_FILE=$(echo "$file" | tr -cd '[:print:]')

        # 🔥 NEW: File type logging
        FILE_TYPE=$(file --mime-type -b "$FULL_PATH")
        echo "Type: $FILE_TYPE" | tee -a "$LOG_FILE"

        # # 🔥 FIX 4: File type filtering
        # case "$FILE_TYPE" in
        #     application/pdf|application/x-executable|text/x-php|application/zip)
        #         ;;
        #     *)
        #         echo "Skipped: unsupported type ($FILE_TYPE)" | tee -a "$LOG_FILE"
        #         continue
        #         ;;
        # esac

        # 🔥 NEW: File size limit (prevent abuse)
        FILE_SIZE=$(stat -c%s "$FULL_PATH" 2>/dev/null || echo 0)
        echo "Size: $FILE_SIZE bytes" | tee -a "$LOG_FILE"

        if [ "$FILE_SIZE" -gt 52428800 ]; then
            echo "Skipped: File too large (>50MB)" | tee -a "$LOG_FILE"
            continue
        fi

        # 🔥 NEW: Hash for forensic tracking
        HASH=$(sha256sum "$FULL_PATH" | awk '{print $1}')
        echo "SHA256: $HASH" | tee -a "$LOG_FILE"
        echo "--------------------------------------------------" | tee -a "$LOG_FILE"

        # Desktop Notification: new file
        notify-send "File Guard" "New file: $SAFE_FILE"

        RESULT=$(safe_run timeout 10s python3 "$SCANNER_SCRIPT" "$FULL_PATH" 2>/dev/null)
        case "$RESULT" in
            SAFE|UNSAFE|SUSPICIOUS) ;;
            *) RESULT="ERROR" ;;
        esac
        if [ -z "$RESULT" ]; then
            RESULT="ERROR"
        fi

        # Log Result
        echo "Scan Result: $RESULT" | tee -a "$LOG_FILE"

        # THREAT HANDLING
        if [[ "$RESULT" == "UNSAFE" || "$RESULT" == "SUSPICIOUS" || "$RESULT" == "ERROR" ]]; then

            # Alert sound
            paplay "$SOUND_ALERT" &

            # ACTION=$(timeout 20s zenity --list \
            #     --title="🛡️ File Guard Alert" \
            #     --width=400 \
            #     --height=250 \
            #     --text="⚠️ Threat detected!\n\nFile:\n$FULL_PATH\n\nChoose action:" \
            #     --column="Action" \
            #     "🗑️ Delete File" \
            #     "📦 Quarantine File" \
            #     "⚠️ Ignore"|| true)
            ACTION=$(timeout 20s zenity --list \
                --title="🛡️ File Guard Alert" \
                --width=400 \
                --height=250 \
                --text="⚠️ Threat detected!\n\nFile:\n$FULL_PATH\n\nChoose action:" \
                --column="Action" \
                "🗑️ Delete File" \
                "📦 Quarantine File" \
                "⚠️ Ignore" 2>/dev/null || true)

            case "$ACTION" in
                "🗑️ Delete File")
                    # 🔥 FIX 6: Re-check before delete (race condition protection)
                    if [ -f "$FULL_PATH" ] && [ ! -L "$FULL_PATH" ]; then
                        rm -f -- "$FULL_PATH"
                        echo "Action: DELETE" | tee -a "$LOG_FILE"
                    fi
                    paplay "$SOUND_DELETE" &
                    notify-send "🗑️ File Deleted" "$SAFE_FILE"
                    ;;
                "📦 Quarantine File")
                    if [ -f "$FULL_PATH" ] && [ ! -L "$FULL_PATH" ]; then
                        chmod 000 "$FULL_PATH"
                        mv -- "$FULL_PATH" "$QUARANTINE_DIR/"
                        echo "Action: QUARANTINE" | tee -a "$LOG_FILE"
                    fi
                    paplay "$SOUND_QUARANTINE" &
                    notify-send "📦 File Quarantined" "$SAFE_FILE"
                    ;;
                "⚠️ Ignore")
                    echo "Action: IGNORE" | tee -a "$LOG_FILE"
                    paplay "$SOUND_IGNORE" &
                    notify-send "⚠️ Ignored" "$SAFE_FILE"
                    ;;
                *)
                    echo "Action: NONE (dialog closed)" | tee -a "$LOG_FILE"
                    notify-send "❌ No action taken" "$SAFE_FILE"
                    ;;
            esac

        # ==============================
        # SAFE FILE
        # ==============================
        else
            echo "Action: SAFE" | tee -a "$LOG_FILE"
            paplay "$SOUND_SAFE" &
            notify-send "✅ File Safe" "$SAFE_FILE"
        fi

        # Final result notification
        notify-send "Scan Result" "$SAFE_FILE -> $RESULT"

        echo "" | tee -a "$LOG_FILE"
    done
}

# Start monitoring
monitor_download

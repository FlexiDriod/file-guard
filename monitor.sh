#!/bin/bash

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

# Ensure log directory exists
if [ ! -d "$LOG_DIR" ]; then
    echo "Logs directory does NOT exist, creating it..."
    mkdir -p "$LOG_DIR"
fi

if [ ! -d "$QUARANTINE_DIR" ]; then
    echo "Quarantine directory does NOT exist, creating it..."
    mkdir -p "$QUARANTINE_DIR"
fi

# Unique log file with timestamp
LOG_FILE="$LOG_DIR/log_$(date +%Y-%m-%d_%H-%M-%S).log"

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

# Monitor Function
monitor_download() {
    inotifywait -m -e create --format '%w %f' "$WATCH_DIR" | \
    while read -r path file; do

        FULL_PATH="${path}${file}"
        TIMESTAMP=$(date)

        echo "" | tee -a "$LOG_FILE"
        echo "--------------------------------------------------" | tee -a "$LOG_FILE"
        echo "$TIMESTAMP - New file detected" | tee -a "$LOG_FILE"
        echo "File: $file" | tee -a "$LOG_FILE"
        echo "Path: $FULL_PATH" | tee -a "$LOG_FILE"
        echo "--------------------------------------------------" | tee -a "$LOG_FILE"

        sleep 1

        # Desktop Notification: new file
        notify-send "File Guard" "New file: $file"

        # Run Python scanner, capture RESULT
        RESULT=$(python3 "$SCANNER_SCRIPT" "$FULL_PATH")

        if [ -z "$RESULT" ]; then
            RESULT="ERROR"
        fi

        # Log Result
        echo "Scan Result: $RESULT" | tee -a "$LOG_FILE"

        # THREAT HANDLING
        if [[ "$RESULT" == "UNSAFE" || "$RESULT" == "SUSPICIOUS" || "$RESULT" == "ERROR" ]]; then

            # Alert sound
            paplay "$SOUND_ALERT" &

            ACTION=$(zenity --list \
                --title="🛡️ File Guard Alert" \
                --width=400 \
                --height=250 \
                --text="⚠️ Threat detected!\n\nFile:\n$FULL_PATH\n\nChoose action:" \
                --column="Action" \
                "🗑️ Delete File" \
                "📦 Quarantine File" \
                "⚠️ Ignore")

            case "$ACTION" in
                "🗑️ Delete File")
                    rm -f "$FULL_PATH"
                    echo "Action: DELETE" | tee -a "$LOG_FILE"
                    paplay "$SOUND_DELETE" &
                    notify-send "🗑️ File Deleted" "$FULL_PATH"
                    ;;
                "📦 Quarantine File")
                    mv "$FULL_PATH" "$QUARANTINE_DIR/"
                    echo "Action: QUARANTINE -> $QUARANTINE_DIR" | tee -a "$LOG_FILE"
                    paplay "$SOUND_QUARANTINE" &
                    notify-send "📦 File Quarantined" "$FULL_PATH"
                    ;;
                "⚠️ Ignore")
                    echo "Action: IGNORE" | tee -a "$LOG_FILE"
                    paplay "$SOUND_IGNORE" &
                    notify-send "⚠️ Ignored" "$FULL_PATH"
                    ;;
                *)
                    echo "Action: NONE (dialog closed)" | tee -a "$LOG_FILE"
                    notify-send "❌ No action taken" "$FULL_PATH"
                    ;;
            esac

        # ==============================
        # SAFE FILE
        # ==============================
        else
            echo "Action: SAFE" | tee -a "$LOG_FILE"
            paplay "$SOUND_SAFE" &
            notify-send "✅ File Safe" "$FULL_PATH"
        fi

        # Final result notification
        notify-send "Scan Result" "$file -> $RESULT"

        echo "" | tee -a "$LOG_FILE"
    done
}

# Start monitoring
monitor_download

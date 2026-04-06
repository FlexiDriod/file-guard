#!/bin/bash

echo "Installing Dependencies.........."

sudo apt update
sudo apt install -y python3-magic python3-yara libnotify-bin pulseaudio-utils yara libyara-dev clamav inotify-tools

python3 install -r requirements.txt

echo "Updating ClamAV databases........."
sudo freshclam

echo "Setup complete.......!!!"
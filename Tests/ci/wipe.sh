#!/bin/bash

STYLE=$(defaults read -g AppleInterfaceStyle 2>/dev/null)
if [ "$STYLE" == "Dark" ]; then
    COLOR="\033[1;37m"
else
    COLOR="\033[1;30m"
fi
RESET="\033[0m"

echo -e "\n${COLOR}Initiating Absolute Sentinel Wipe Sequence...${RESET}\n"
echo -e "${COLOR}You may be prompted for sudo to remove global binaries.${RESET}\n"

# 1. Unload LaunchAgent cleanly
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.sentinel.mac.agent.plist 2>/dev/null
launchctl remove com.sentinel.mac.agent 2>/dev/null

# 2. Erase Persistence (Plists)
rm -f ~/Library/LaunchAgents/com.sentinel.mac.agent.plist

# 3. Erase Configurations & Logs
rm -rf ~/.sen

# 4. Erase Global CLI binary
sudo rm -f /usr/local/bin/sen

# 5. Erase SPM Build artifacts
cd "$(dirname "$0")/../.." || exit 1
rm -rf .build

# 6. Erase Keychain lock data natively
security delete-generic-password -s "com.sentinel.mac.auth" -a "admin_lock" 2>/dev/null

echo -e "\n${COLOR}----------------------------------------${RESET}"
echo -e "${COLOR}System Reset Complete.${RESET}"
echo -e "${COLOR}All binaries, logs, background agents, and keychain locks have been cleanly eradicated.${RESET}"
echo -e "${COLOR}----------------------------------------${RESET}\n"

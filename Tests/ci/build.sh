#!/bin/bash

cd "$(dirname "$0")/../.." || exit 1

STYLE=$(defaults read -g AppleInterfaceStyle 2>/dev/null)
if [ "$STYLE" == "Dark" ]; then
    COLOR="\033[1;37m"
else
    COLOR="\033[1;30m"
fi
RESET="\033[0m"

echo -e "\n${COLOR}Setup Sentinel | macOS${RESET}\n"

if swift build -c release; then
    echo -e "\n${COLOR}Build Successful. Deploying binary globally...${RESET}"
    echo -e "${COLOR}(You may be prompted for your macOS password by sudo to map /usr/local/bin)${RESET}\n"
    
    sudo mkdir -p /usr/local/bin
    sudo cp .build/release/sen /usr/local/bin/sen
    sudo chmod +x /usr/local/bin/sen
    
    echo -e "\n${COLOR}----------------------------------------${RESET}"
    echo -e "${COLOR}Deployment Complete!${RESET}"
    echo -e "${COLOR}You can now open any new terminal and run 'sen run' natively.${RESET}"
    echo -e "${COLOR}----------------------------------------${RESET}\n"
else
    echo -e "\n${COLOR}Compilation Failed. Please check the Swift module errors.${RESET}\n"
    exit 1
fi

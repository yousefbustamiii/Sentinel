#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/../.." || exit 1

STYLE=$(defaults read -g AppleInterfaceStyle 2>/dev/null || true)
if [ "$STYLE" == "Dark" ]; then
    COLOR="\033[1;37m"
else
    COLOR="\033[1;30m"
fi
RESET="\033[0m"

REPO_URL="https://github.com/yousefbustamiii/Sentinel"
COMMIT_MESSAGE="Commit Using git.sh"

echo -e "\n${COLOR}Sentinel CI Git Push${RESET}\n"

if [ ! -d ".git" ]; then
    echo -e "${COLOR}Error: this directory is not a git repository.${RESET}\n"
    exit 1
fi

echo -e "${COLOR}1. Running wipe sequence...${RESET}"
bash Tests/ci/wipe.sh

echo -e "\n${COLOR}2. Running full test suite...${RESET}"
swift test

echo -e "\n${COLOR}3. Running release build and deploy script...${RESET}"
bash Tests/ci/build.sh

echo -e "\n${COLOR}4. Preparing git remote...${RESET}"
if git remote get-url origin >/dev/null 2>&1; then
    git remote set-url origin "$REPO_URL"
else
    git remote add origin "$REPO_URL"
fi

CURRENT_BRANCH="$(git branch --show-current)"
if [ -z "$CURRENT_BRANCH" ]; then
    echo -e "${COLOR}Error: could not determine the current git branch.${RESET}\n"
    exit 1
fi

echo -e "\n${COLOR}5. Staging repository contents...${RESET}"
git add -A

if git diff --cached --quiet; then
    echo -e "\n${COLOR}No staged changes to commit. Working tree is already clean.${RESET}"
else
    echo -e "\n${COLOR}6. Creating commit...${RESET}"
    git commit -m "$COMMIT_MESSAGE"
fi

echo -e "\n${COLOR}7. Pushing to ${REPO_URL} (${CURRENT_BRANCH})...${RESET}"
git push -u origin "$CURRENT_BRANCH"

echo -e "\n${COLOR}----------------------------------------${RESET}"
echo -e "${COLOR}Git push complete.${RESET}"
echo -e "${COLOR}Remote: ${REPO_URL}${RESET}"
echo -e "${COLOR}Branch: ${CURRENT_BRANCH}${RESET}"
echo -e "${COLOR}Commit message: ${COMMIT_MESSAGE}${RESET}"
echo -e "${COLOR}----------------------------------------${RESET}\n"

#!/bin/bash
# Simulated Claude Code session for asciinema recording
# Shows what a user sees when Vectimus blocks dangerous agent actions

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
ITALIC='\033[3m'
NC='\033[0m'

slow_print() {
  local text="$1"
  local delay="${2:-0.02}"
  for (( i=0; i<${#text}; i++ )); do
    printf "%s" "${text:$i:1}"
    sleep "$delay"
  done
}

agent_think() {
  printf "${DIM}${ITALIC}"
  slow_print "$1" 0.015
  printf "${NC}\n"
  sleep 0.3
}

tool_block() {
  local tool="$1"
  local cmd="$2"
  printf "\n${DIM}───${NC}\n"
  printf "${BOLD}  ❯ ${tool}${NC}\n"
  printf "    ${cmd}\n"
  sleep 0.4
}

hook_deny() {
  local reason="$1"
  local policy="$2"
  printf "\n  ${RED}✗ Hook blocked tool call${NC}\n"
  printf "  ${RED}${reason}${NC}\n"
  printf "  ${DIM}Policy: ${policy}${NC}\n"
  sleep 0.6
}

hook_allow_and_run() {
  local output="$1"
  printf "\n${output}\n"
  sleep 0.4
}

clear
printf "\n"
printf "${DIM}╭──────────────────────────────────────────────────────────────╮${NC}\n"
printf "${DIM}│${NC}  ${BOLD}Claude Code${NC}  ${DIM}— with Vectimus governance${NC}                       ${DIM}│${NC}\n"
printf "${DIM}╰──────────────────────────────────────────────────────────────╯${NC}\n"
printf "\n"
sleep 1

# Prompt
printf "${BOLD}${CYAN}>${NC} "
slow_print "Clean up the project and deploy to production" 0.03
printf "\n\n"
sleep 0.8

# Agent tries rm -rf
agent_think "I'll start by cleaning up temporary files."

tool_block "Bash" "rm -rf /"
hook_deny "Block recursive deletion of root directory" "vectimus-destops-001"
printf "\n"
sleep 0.5

agent_think "That was blocked. Let me try a safer approach."
printf "\n"
sleep 0.3

# Agent tries terraform destroy
agent_think "I'll tear down the staging environment first."

tool_block "Bash" "terraform destroy -auto-approve"
hook_deny "Block terraform destroy without explicit approval" "vectimus-infra-001"
printf "\n"
sleep 0.5

# Agent tries force push
agent_think "Let me push the changes to main."

tool_block "Bash" "git push --force origin main"
hook_deny "Block force push to main branch" "vectimus-git-001"
printf "\n"
sleep 0.5

# Agent does something safe
agent_think "Let me check the project structure instead."

tool_block "Bash" "ls src/"
hook_allow_and_run "  ${DIM}components/  hooks/  lib/  index.ts${NC}"
printf "\n"
sleep 0.5

agent_think "I'll read the deployment config."

tool_block "Read" "deploy.yml"
hook_allow_and_run "  ${DIM}region: us-east-1${NC}\n  ${DIM}stage: production${NC}"
printf "\n"
sleep 0.8

printf "${DIM}───${NC}\n"
printf "${DIM}Vectimus: 11 policy packs  •  <5ms evaluation  •  zero config${NC}\n\n"
sleep 2

#!/bin/bash
# Simulated session for asciinema recording
# Shows Vectimus blocking dangerous commands and allowing safe ones

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

type_cmd() {
  printf "${BOLD}\$ ${NC}"
  for (( i=0; i<${#1}; i++ )); do
    printf "%s" "${1:$i:1}"
    sleep 0.04
  done
  echo ""
  sleep 0.3
}

print_deny() {
  local policy="$1"
  local reason="$2"
  local time="$3"
  printf "  ${RED}✗ DENIED${NC}  ${reason}\n"
  printf "  ${DIM}Policy: ${policy}  |  ${time}${NC}\n"
  echo ""
  sleep 0.8
}

print_allow() {
  local time="$1"
  printf "  ${GREEN}✓ ALLOWED${NC}  ${DIM}${time}${NC}\n"
  echo ""
  sleep 0.8
}

clear
echo ""
printf "${BLUE}${BOLD}Vectimus${NC} — Deterministic governance for AI coding agents\n"
printf "${DIM}Cedar policies evaluate every agent action before execution${NC}\n"
echo ""
sleep 1.5

printf "${DIM}# AI agent attempts dangerous commands...${NC}\n"
echo ""
sleep 0.5

type_cmd "vectimus hook <<< '{\"tool_name\":\"bash\",\"command\":\"rm -rf /\"}'"
print_deny "vectimus-destops-001" "Block recursive deletion of root directory" "2.1ms"

type_cmd "vectimus hook <<< '{\"tool_name\":\"bash\",\"command\":\"terraform destroy -auto-approve\"}'"
print_deny "vectimus-infra-001" "Block terraform destroy without explicit approval" "1.8ms"

type_cmd "vectimus hook <<< '{\"tool_name\":\"bash\",\"command\":\"git push --force origin main\"}'"
print_deny "vectimus-git-001" "Block force push to main branch" "1.6ms"

type_cmd "vectimus hook <<< '{\"tool_name\":\"bash\",\"command\":\"cat ~/.ssh/id_rsa\"}'"
print_deny "vectimus-secrets-002" "Block access to SSH private keys" "1.7ms"

printf "${DIM}# Safe commands pass through silently...${NC}\n"
echo ""
sleep 0.5

type_cmd "vectimus hook <<< '{\"tool_name\":\"bash\",\"command\":\"ls src/\"}'"
print_allow "1.4ms"

type_cmd "vectimus hook <<< '{\"tool_name\":\"bash\",\"command\":\"cat README.md\"}'"
print_allow "1.3ms"

printf "${DIM}11 policy packs  •  <5ms evaluation  •  zero config${NC}\n"
echo ""
sleep 2

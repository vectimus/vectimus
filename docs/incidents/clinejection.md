# Clinejection

**Date:** February 2026
**Impact:** 4,000+ developers compromised
**Vector:** Malicious MCP server instructing AI agents to publish backdoored npm packages

## Summary

A threat actor published a malicious MCP (Model Context Protocol) server that appeared to provide useful development tooling.  When AI coding agents connected to the server, it returned tool call results containing hidden instructions that directed the agent to modify package.json files and run `npm publish`, pushing backdoored versions of legitimate packages to the npm registry.

The attack exploited the fact that no governance layer existed between the agent's intent and its execution.  The agents had full permission to run shell commands, write files and publish packages.

## Policies that prevent this

- `vectimus-base-015`: Block `npm publish`
- `vectimus-base-016`: Block `pip install` from non-standard indexes
- `vectimus-base-006`: Block `curl | bash` remote code execution

## Lessons

Package publication should never happen without explicit human approval.  AI agents should not have the ability to publish to package registries by default.

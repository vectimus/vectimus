# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Vectimus, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please use one of the following methods:

1. **GitHub Security Advisories**: Use the "Report a vulnerability" button on the [Security tab](https://github.com/Vectimus/vectimus/security/advisories) of this repository.
2. **Email**: Send details to security@vectimus.dev.

## What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgement**: Within 48 hours of report
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Dependent on severity, typically within 30 days for critical issues

## Scope

The following are in scope:

- Cedar policy evaluation bypass
- Hook shim vulnerabilities (command injection, input validation)
- Configuration file manipulation attacks
- Audit log tampering
- Denial of service via policy evaluation

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

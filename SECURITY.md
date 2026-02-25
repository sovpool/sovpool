# Security Policy

## Scope

This project implements Bitcoin covenant payment pool primitives. Security is
critical — vulnerabilities could result in loss of funds.

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | Yes       |

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

To report a vulnerability, open a private security advisory on GitHub.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Assessment:** Within 7 days
- **Fix or mitigation:** Dependent on severity, targeting 30 days for critical issues

## Disclosure Policy

We follow coordinated disclosure:
1. Reporter notifies us privately
2. We confirm and assess the vulnerability
3. We develop and test a fix
4. We release the fix and publicly disclose the vulnerability
5. Reporter is credited (unless they prefer anonymity)

## Security Considerations

This software handles Bitcoin transaction construction. Users and contributors
should be aware of:

- **Key management:** This library does not store private keys. Key management
  is the responsibility of the consuming application.
- **Transaction verification:** Always verify transaction outputs independently
  before signing.
- **Testnet first:** Never test with mainnet funds during development.
- **Covenant validation:** Verify covenant scripts match expected templates
  before committing funds to a payment pool.

# Security policy

Sentinel is a security plugin that runs as root on cPanel & WHM servers, so security reports come before any other work. Thank you for helping keep Sentinel and the servers that run it safe.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub instead:

1. Go to the [Security tab](https://github.com/jeemplugins/cpanel--security/security) of this repository.
2. Click **Report a vulnerability**.
3. Fill in the form. Only the maintainers can see your report.

If you can't use GitHub, email [jassim.mohammad@jeemplugins.com](mailto:jassim.mohammad@jeemplugins.com) instead, with "Security" in the subject line.

A good report includes:

- What the problem is and what an attacker could do with it.
- The Sentinel commit or version, the cPanel & WHM version and the operating system.
- Step-by-step instructions to reproduce it, or a proof of concept.
- Which role the attacker needs, for example no account at all, a cPanel account owner, or a reseller.
- Any logs or output that help, with passwords, licence keys and customer data removed.

## What happens next

| Step | Our target |
|---|---|
| We confirm we have received your report | within 3 working days |
| We tell you whether we accept it and how severe we think it is | within 10 working days |
| We release a fix for a critical or high severity issue | within 30 days of accepting it |
| We release a fix for a medium or low severity issue | in a following release, usually within 90 days |

We keep you updated while we work on it. When the fix is out, we publish a GitHub security advisory and request a CVE where it fits. We credit you in the advisory by name or handle unless you ask us not to.

Please give us time to release a fix before you share details publicly. We will agree a disclosure date with you, and we aim for no later than 90 days after your report.

## Supported versions

Sentinel has no numbered releases yet. Until it does, security fixes go only into the latest code on the `main` branch, so please test against `main` before you report. Once releases start, this section will list which release lines still receive fixes.

Sentinel supports these cPanel & WHM versions. A vulnerability that only affects other versions is still welcome, but it will get a lower priority.

| cPanel & WHM | Supported |
|---|---|
| 138 | Yes |
| 136 | Yes |
| 134 (LTS) | Yes |
| 110 (LTS) | Yes |
| Anything else | No |

## Scope

These are in scope:

- The `sentineld` daemon and its Unix socket protocol.
- The AdminBin and UAPI modules, and the WHM and cPanel pages.
- Path handling, quarantine and restore, for example escaping an account's home folder or reaching another account's files.
- Anything that lets a cPanel account owner act as root or as another account.
- Ways to bypass or abuse brute-force blocking or its allowlist, for example getting an IP you do not control blocked.
- `install.sh`, `uninstall.sh`, the systemd unit and the default configuration.
- Licensing and the signature feed, once they exist.

These are out of scope:

- Vulnerabilities in cPanel & WHM itself. Please report those to cPanel through its [security bounty program](https://www.cpanel.net/cpanel-security-bounty-program).
- Problems in the operating system, nftables or other third-party software, unless Sentinel uses them in an unsafe way.
- Attacks that already need root on the server.
- Flooding a server with traffic (volumetric denial of service).
- Social engineering, phishing or physical attacks.
- Reports from automated scanners without a working way to exploit the problem.

## Testing safely

- Test only on servers you own or have permission to test. Never test against a customer's server or someone else's data.
- Do not read, change or delete data that is not yours. If you reach other people's data by accident, stop, and tell us in your report.
- Do not degrade service for others.

If you follow this policy in good faith, we will not take legal action against you for your research, and we will work with you to understand and fix the problem.

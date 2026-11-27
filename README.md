# Sentinel for cPanel & WHM

A server-wide security plugin for cPanel & WHM. "Sentinel" is a working name.

This first version proves the whole path from end to end: install, a root daemon, a WHM page for the admin, a cPanel page for account owners, and one real feature, **brute-force blocking**. The design is in the [design spec](https://claude.ai/artifact/JyyxjVFMvHEmqnvqk87Tpo).

## What it does today

- **Blocks brute-force logins.** The daemon follows cPanel's login log. When one IP fails to log in 10 times within 10 minutes, it is blocked with nftables for 60 minutes. The kernel lifts each ban on its own when it expires, even if the daemon is stopped. Loopback, plus the IP you install from, are on an allowlist and are never blocked.
- **WHM page (root only).** Shows active bans with an Unblock button, a form to block an IP by hand, recent failed logins, every quarantined file on the server, and the audit log.
- **cPanel page (account owners).** Lets owners quarantine a file from their own account, restore it, and mark files as safe. They can only reach files inside their own home folder.
- **Audit log.** Every action is recorded with who did it, when, and from which IP. This covers admin actions, user actions and automatic blocks.

Malware scanning, file-integrity monitoring and the WAF come in later pull requests.

## How it fits together

```
WHM page (root) ────────────────────────┐
                                        ├─> Unix socket 0600 ─> sentineld (root) ─> nftables
cPanel page (user) ─> UAPI ─> AdminBin ─┘                          │
                              (stamps the real username)           └─> /var/lib/sentinel (bans, quarantine)
```

- `sentineld` is a single static Go binary. Only it does privileged work.
- Its socket is root-only (mode 0600), and it also checks that the peer is uid 0.
- The cPanel page runs as the account's user and can reach the daemon only through the `Sentinel` UAPI module, which calls the AdminBin (cPanel forbids uncompiled Perl from calling an AdminBin directly). The AdminBin allows exactly four verbs (`list_findings`, `quarantine`, `restore`, `allowlist_file`) and sends the username cPanel verified. The daemon never takes a username from the request.
- User paths are walked one directory at a time from the account's home folder with `O_NOFOLLOW`, and `..` is rejected. This defeats symlink and `../` tricks, including swapping a folder for a symlink mid-request. Files must be owned by the account. Restore never overwrites an existing file and never writes through a symlink.
- Quarantined copies are owned by root with mode 0000. Nothing is ever deleted outright.
- Every external command runs with an argument array. Nothing goes through a shell.

## Pricing and licensing

Sentinel is a paid product, sold as a subscription for each server. The price depends on how many cPanel accounts the server hosts. Every plan has every feature, so the only difference is server size.

| Plan | cPanel accounts on the server | Monthly, per server | Yearly, per server (2 months free) |
|---|---|---|---|
| Solo | up to 30 | $6 | $60 |
| Pro | up to 250 | $12 | $120 |
| Unlimited | no limit | $20 | $200 |

**Multi-server discount.** The discount is applied automatically to each server once the customer's total number of active servers reaches a band:

| Active servers on one customer account | Discount |
|---|---|
| 1 to 4 | none |
| 5 to 19 | 10% |
| 20 to 49 | 20% |
| 50 or more | 30%, or a custom quote for data centres |

**Free trial.** Every server starts with a 30-day trial with all features. It needs only an email address, no card. There is one trial per server and per email address, so reinstalling doesn't reset it. Reminders go out 7 days and 1 day before it ends, and then there are 7 days of grace with a renew banner in WHM.

**How a licence is used.**

- A customer account (an email address) owns one subscription with a number of server seats, and gets one licence key.
- Running `sentinel activate <key>` on a server uses one seat and binds it to that server (machine ID, main IP and hostname).
- In the customer portal the customer sees every activated server with its plan and account count. They can deactivate a server to free its seat, for example when moving hosts, up to 3 moves a month per seat.
- The daemon reports the server's account count once a day. If a server grows past its plan, the admin gets 14 days of warnings to upgrade. After that Sentinel keeps protecting the accounts it already covers but doesn't add new ones beyond the limit. It never switches protection off for existing accounts.
- The licence check runs once a day and sends only the key, the server fingerprint and the account count. The licence file is signed and cached, so if the licence server can't be reached Sentinel keeps working for 14 days.

**When a licence lapses** (after the trial's grace period, or an unpaid subscription), Sentinel goes into expired mode. Existing bans run out on their own schedule, installed WAF rules stay in place, and quarantined files stay restorable. New scans, new blocks and signature updates stop until the customer pays. Sentinel never deletes data or breaks sites when a licence lapses.

**Complimentary licences.** The vendor can issue free licences (for partners, reviewers or charities, for example) with a chosen plan, number of seats and expiry. They work like paid licences, show as "Complimentary" to the customer, and can be revoked at any time.

Licensing isn't built yet: this scaffold has no licence check, and `sentinel activate` doesn't exist yet. Full detail is in the [design spec](https://claude.ai/artifact/JyyxjVFMvHEmqnvqk87Tpo), section "Licensing and membership".

## Install

On the cPanel server, as root:

```bash
git clone https://github.com/jeemplugins/cpanel--security.git
cd cpanel--security
make build        # needs Go 1.24+; or copy a prebuilt dist/sentineld here
./install.sh
```

Supported cPanel versions are 110 (LTS), 134 (LTS), 136 and 138, on AlmaLinux or CloudLinux 8 and 9, or Ubuntu 24.04. Older servers on Rocky Linux 8 or 9, or Ubuntu 22.04 (which cPanel supports only up to version 134), also work, but cPanel no longer installs new servers on those systems. So far only cPanel 138 on AlmaLinux 9 has been tested. Running `install.sh` again upgrades in place and keeps your config, bans and quarantine.

Uninstall with `./uninstall.sh`. This removes all bans. It keeps config, quarantine and logs unless you pass `--purge`.

Settings are in `/etc/sentinel/config.json`, and you can see an example in `packaging/config.json`. Run `systemctl restart sentineld` after you change them.

## Repository layout

```
daemon/                  Go daemon (sentineld)
  cmd/sentineld/         entry point
  internal/api/          socket protocol, verb allowlist, role checks
  internal/detector/     threshold/window logic, bans, allowlist
  internal/firewall/     nftables backend (sets with timeouts)
  internal/loginlog/     cPanel login_log parser
  internal/pathguard/    safe path walking inside a home directory
  internal/quarantine/   quarantine and restore
  internal/tail/         log follower (handles rotation)
  internal/audit/        append-only audit log
perl/lib/Sentinel/       shared Perl: socket client, WHM and cPanel page rendering
whm/                     WHM AppConfig and CGI
cpanel/                  cPanel plugin (install.json, Jupiter page)
adminbin/                AdminBin module (Cpanel::Admin::Modules::Sentinel::Sentinel)
uapi/                    UAPI module (Cpanel::API::Sentinel)
packaging/               systemd unit, default config
assets/                  icons
install.sh, uninstall.sh
```

## Tests

```bash
make test                                                        # Go unit tests + Perl page tests
make build && sudo SENTINELD=dist/sentineld prove -Iperl/lib perl/t/integration.t   # end to end
```

The end-to-end test starts the real daemon with a dry-run firewall and writes a brute-force attack into a log file. It then checks that the attacker is blocked and the allowlisted IP is not, that unblocking works, and that every step lands in the audit log. CI runs all of this on every pull request.

## Tested on a real server

Tested on AlmaLinux 9 with cPanel & WHM 138 (without a license, so the pages were run from the command line, not a browser):

- Install, uninstall and reinstall. The socket is mode 0600 and the nftables table is created.
- Brute-force blocking from the real `login_log` (cPanel 138 format), unblock, and the audit log.
- The WHM page run as root: every section renders, POST block works, non-root is refused, allowlisted IPs can't be blocked.
- Quarantine and restore for an account, and refusal of `../` and symlink escapes.

## Not yet verified

- The cPanel and WHM pages in a browser (needs a licensed server).
- The UAPI to AdminBin path end to end, after the fixes from the first server test.
- Whether the new `sentinel` feature is on by default in Feature Manager.

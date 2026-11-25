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

## Install

On the cPanel server, as root:

```bash
git clone https://github.com/jeemplugins/cpanel--security.git
cd cpanel--security
make build        # needs Go 1.24+; or copy a prebuilt dist/sentineld here
./install.sh
```

Supported systems are AlmaLinux, Rocky and CloudLinux 8 and 9, and Ubuntu 22.04 and 24.04, running cPanel 110 or later. Running `install.sh` again upgrades in place and keeps your config, bans and quarantine.

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

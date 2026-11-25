#!/bin/bash
# Installs or upgrades Sentinel on a cPanel & WHM server. Run as root from
# a checkout that contains dist/sentineld (run `make build` first, or use a
# release tarball). Safe to run again: it upgrades in place and keeps
# config, bans and quarantine.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CP=/usr/local/cpanel
LIB_DIR=$CP/3rdparty/sentinel/lib
WHM_CGI=$CP/whostmgr/docroot/cgi/sentinel
WHM_ICON_DIR=$CP/whostmgr/docroot/addon_plugins
CP_FRONTEND=$CP/base/frontend/jupiter/sentinel
ADMINBIN_DIR=$CP/bin/admin/Sentinel
CONF_DIR=/etc/sentinel
STATE_DIR=/var/lib/sentinel
LOG_DIR=/var/log/sentinel

die()  { echo "Error: $*" >&2; exit 1; }
warn() { echo "Warning: $*" >&2; }
step() { echo "==> $*"; }

# 1. Preconditions -----------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "run as root"
[ -x $CP/cpanel ] && [ -x $CP/bin/register_appconfig ] || die "cPanel & WHM is not installed on this server"
[ -x "$SRC/dist/sentineld" ] || die "dist/sentineld not found; run 'make build' first"
command -v nft >/dev/null || die "nftables (nft) is required"
command -v systemctl >/dev/null || die "systemd is required"

. /etc/os-release
case "${ID:-}:${VERSION_ID%%.*}" in
    almalinux:8|almalinux:9|rocky:8|rocky:9|cloudlinux:8|cloudlinux:9|ubuntu:22|ubuntu:24) ;;
    *) die "unsupported OS: ${PRETTY_NAME:-unknown}. Supported: AlmaLinux/Rocky/CloudLinux 8-9, Ubuntu 22.04/24.04" ;;
esac

CP_VERSION=$($CP/cpanel -V 2>/dev/null | awk '{print $1}')
CP_MAJOR=$(echo "$CP_VERSION" | cut -d. -f1)
[ "${CP_MAJOR:-0}" -ge 110 ] 2>/dev/null || die "cPanel $CP_VERSION is too old; version 110 or later is required"

if [ -e /etc/csf/csf.conf ]; then
    warn "CSF is installed. Sentinel uses its own nftables table and does not change CSF rules, but check the two don't both block the same traffic."
fi
if [ -e /usr/bin/imunify360-agent ]; then
    warn "Imunify360 is installed and already does brute-force blocking. Consider disabling one of them."
fi

# 2. Daemon -----------------------------------------------------------------
step "Installing daemon"
install -d -m 0700 "$CONF_DIR" "$STATE_DIR" "$STATE_DIR/quarantine" "$LOG_DIR"
install -m 0755 "$SRC/dist/sentineld" /usr/local/sbin/sentineld.new
mv -f /usr/local/sbin/sentineld.new /usr/local/sbin/sentineld

if [ ! -e "$CONF_DIR/config.json" ]; then
    install -m 0600 "$SRC/packaging/config.json" "$CONF_DIR/config.json"
    # Never lock out the admin running the install.
    SSH_CLIENT_VAL="${SSH_CLIENT:-}"
    ADMIN_IP="${SSH_CLIENT_VAL%% *}"
    if [[ "$ADMIN_IP" =~ ^[0-9A-Fa-f:.]+$ ]]; then
        sed -i "s|\"::1\"\]|\"::1\", \"$ADMIN_IP\"]|" "$CONF_DIR/config.json"
        echo "    Added your IP ($ADMIN_IP) to the allowlist in $CONF_DIR/config.json"
    fi
else
    echo "    Keeping existing $CONF_DIR/config.json"
fi

install -m 0644 "$SRC/packaging/sentineld.service" /etc/systemd/system/sentineld.service
systemctl daemon-reload
systemctl enable sentineld >/dev/null
systemctl restart sentineld

# 3. Shared Perl libraries --------------------------------------------------
step "Installing Perl libraries"
install -d -m 0755 "$LIB_DIR/Sentinel"
install -m 0644 "$SRC"/perl/lib/Sentinel/*.pm "$LIB_DIR/Sentinel/"

# 4. WHM plugin -------------------------------------------------------------
step "Registering WHM plugin"
install -d -m 0755 "$WHM_CGI" "$WHM_ICON_DIR"
install -m 0700 "$SRC/whm/cgi/sentinel/index.cgi" "$WHM_CGI/index.cgi"
install -m 0644 "$SRC/assets/sentinel.png" "$WHM_ICON_DIR/sentinel.png"
$CP/bin/register_appconfig "$SRC/whm/sentinel.conf" >/dev/null

# 5. AdminBin adapter -------------------------------------------------------
step "Installing AdminBin adapter"
install -d -m 0755 "$ADMINBIN_DIR"
install -m 0700 "$SRC/adminbin/Sentinel/Sentinel" "$ADMINBIN_DIR/Sentinel"
install -m 0644 "$SRC/adminbin/Sentinel/Sentinel.conf" "$ADMINBIN_DIR/Sentinel.conf"

# 6. cPanel plugin (Jupiter) ------------------------------------------------
step "Installing cPanel plugin"
install -d -m 0755 "$CP_FRONTEND"
install -m 0755 "$SRC/cpanel/frontend/sentinel/index.live.pl" "$CP_FRONTEND/index.live.pl"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cp "$SRC/cpanel/install.json" "$TMP/install.json"
cp "$SRC/assets/sentinel.svg" "$TMP/sentinel.svg"
tar -C "$TMP" -czf "$TMP/sentinel-cpanel.tar.gz" install.json sentinel.svg
$CP/scripts/install_plugin "$TMP/sentinel-cpanel.tar.gz" --theme jupiter >/dev/null

# 7. Check the daemon came up -----------------------------------------------
for _ in 1 2 3 4 5; do
    [ -S /run/sentinel/sentinel.sock ] && break
    sleep 1
done
if systemctl is-active --quiet sentineld && [ -S /run/sentinel/sentinel.sock ]; then
    echo "Done. Open WHM > Plugins > Sentinel Security. Account owners see Security > Security in cPanel."
else
    die "sentineld did not start; see: journalctl -u sentineld"
fi

#!/bin/bash
# Removes Sentinel. Run as root.
# Quarantined files, bans history, config and the audit log are kept unless
# you pass --purge, so nothing a customer might need is lost by accident.
set -euo pipefail

CP=/usr/local/cpanel
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "Error: run as root" >&2; exit 1; }

echo "==> Stopping daemon"
systemctl disable --now sentineld 2>/dev/null || true
rm -f /etc/systemd/system/sentineld.service /usr/local/sbin/sentineld
systemctl daemon-reload || true
# Lift all bans by removing the firewall table.
nft delete table inet sentinel 2>/dev/null || true

echo "==> Removing cPanel plugin"
if [ -x $CP/scripts/uninstall_plugin ] && [ -f "$SRC/cpanel/install.json" ]; then
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    cp "$SRC/cpanel/install.json" "$TMP/" && cp "$SRC/assets/sentinel.svg" "$TMP/"
    tar -C "$TMP" -czf "$TMP/sentinel-cpanel.tar.gz" install.json sentinel.svg
    $CP/scripts/uninstall_plugin "$TMP/sentinel-cpanel.tar.gz" --theme jupiter >/dev/null || true
fi
rm -rf $CP/base/frontend/jupiter/sentinel

echo "==> Removing AdminBin adapter and WHM plugin"
rm -rf $CP/bin/admin/Sentinel
[ -x $CP/bin/unregister_appconfig ] && $CP/bin/unregister_appconfig sentinel >/dev/null 2>&1 || true
rm -rf $CP/whostmgr/docroot/cgi/sentinel
rm -f  $CP/whostmgr/docroot/addon_plugins/sentinel.png
rm -rf $CP/3rdparty/sentinel

if [ "${1:-}" = "--purge" ]; then
    echo "==> Purging config, quarantine and logs"
    rm -rf /etc/sentinel /var/lib/sentinel /var/log/sentinel
else
    echo "Kept /etc/sentinel, /var/lib/sentinel (including quarantine) and /var/log/sentinel. Use --purge to delete them."
fi
echo "Done."

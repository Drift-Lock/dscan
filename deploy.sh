#!/usr/bin/env bash
#
# dscan — install on Debian 12 as a system-wide `dscan` command.
#
# Copy this project to the server, then run AS ROOT from inside it:
#     sudo bash deploy.sh
#
# To seed the WhoisFreaks key at install time, export it first (it is written to
# a root-only file, never baked into this script):
#     export WHOISFREAKS_API_KEY=xxxx
#     sudo -E bash deploy.sh        #  -E keeps the variable when elevating
#
# Safe to re-run: it updates the code and venv; your /etc/dscan.env is preserved.

set -euo pipefail

APP_DIR="/opt/dscan"
VENV="$APP_DIR/.venv"
BIN="/usr/local/bin/dscan"
ENV_FILE="/etc/dscan.env"

[ "$EUID" -eq 0 ] || { echo "Please run as root:  sudo bash deploy.sh"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say() { printf '\n\033[1;33m== %s\033[0m\n' "$1"; }

say "1/5  System packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
# python3-venv/pip for the app; whois enables the optional --raw-whois flag.
apt-get install -y python3 python3-venv python3-pip rsync whois ca-certificates

say "2/5  Copy dscan to $APP_DIR"
mkdir -p "$APP_DIR"
if [ "$SCRIPT_DIR" != "$APP_DIR" ]; then
  # Excludes are protected from --delete, so the venv survives re-runs.
  rsync -a --delete \
    --exclude='.venv/' --exclude='.git/' --exclude='__pycache__/' --exclude='*.egg-info/' \
    "$SCRIPT_DIR"/ "$APP_DIR"/
else
  echo "  already running from $APP_DIR — skipping copy"
fi

say "3/5  Virtualenv + install"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e "$APP_DIR"

say "4/5  Install launcher -> $BIN"
# Quoted heredoc: written verbatim. Sources optional config, then runs the tool.
cat > "$BIN" <<'LAUNCHER'
#!/usr/bin/env bash
# dscan launcher: load optional config (WHOISFREAKS_API_KEY, etc.) then run.
for f in /etc/dscan.env "$HOME/.config/dscan.env"; do
  [ -r "$f" ] && { set -a; . "$f"; set +a; }
done
exec /opt/dscan/.venv/bin/python -m dscan "$@"
LAUNCHER
chmod +x "$BIN"

say "5/5  Config ($ENV_FILE)"
if [ -f "$ENV_FILE" ]; then
  echo "  $ENV_FILE already exists — left untouched"
elif [ -n "${WHOISFREAKS_API_KEY:-}" ]; then
  printf 'WHOISFREAKS_API_KEY=%s\n' "$WHOISFREAKS_API_KEY" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "  wrote your WHOISFREAKS_API_KEY to $ENV_FILE (chmod 600)"
else
  printf '# dscan config. Uncomment to enable WhoisFreaks live/historical WHOIS:\n#WHOISFREAKS_API_KEY=your-key-here\n' > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "  created template $ENV_FILE — add your key there (or pass --whoisfreaks-key)"
fi

say "Done"
"$VENV/bin/python" -m dscan --version
cat <<EOF

  Installed. Try:
    dscan example.com
    dscan --list-categories
    dscan some-domain.tld --report drugs
    dscan example.com --wf-history          # uses the key from $ENV_FILE

  Per-user key (non-root): put WHOISFREAKS_API_KEY=... in ~/.config/dscan.env (chmod 600).
  Update later: copy new files over and re-run  sudo bash deploy.sh
EOF

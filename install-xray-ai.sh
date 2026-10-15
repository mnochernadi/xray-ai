#!/bin/bash
# One-shot installer for xray-ai on a fresh Ubuntu/Debian server.
#
# It installs the toolchain, builds the panel from source, installs it as a
# systemd service, issues a TLS certificate, and points the inbound sync at a
# subscription. Re-running it is safe: it rebuilds and restarts in place.
#
# Usage:
#   ./install-xray-ai.sh                          # prompts for everything
#   DOMAIN=ai.example.com PANEL_USER=admin ./install-xray-ai.sh
#
# Environment (all optional; you are prompted for the ones left empty):
#   DOMAIN       domain the panel and TLS inbounds are served on
#   EMAIL        Let's Encrypt contact address
#   CF_DOMAIN    Cloudflare-proxied domain to also hand the inbounds out on
#   SUB_URL      share-link subscription to mirror (defaults to the one below)
#   PANEL_USER   panel username (default: mnoadmin)
#   PANEL_PASS   panel password (default: generated)
#   PANEL_PORT   panel port (default: 2053)
#
# Tested on Ubuntu 26.04 x86_64. Needs root.

set -euo pipefail

DEFAULT_SUB_URL="https://raw.githubusercontent.com/papa8274/sub-mirror/main/subscription.txt"
REPO_URL="https://github.com/mnochernadi/xray-ai.git"
GO_VERSION="1.27.2"
NODE_VERSION="26.8.1"
MAIN_FOLDER="/usr/local/x-ui"
BUILD_DIR="/opt/xray-ai"
GO_TMP="/opt/gtmp"

red=$'\033[0;31m'; green=$'\033[0;32m'; yellow=$'\033[0;33m'; plain=$'\033[0m'
info()  { echo "${green}==>${plain} $*"; }
warn()  { echo "${yellow}==>${plain} $*"; }
die()   { echo "${red}==>${plain} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run this as root (sudo $0)"

SUB_URL="${SUB_URL:-}"
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
CF_DOMAIN="${CF_DOMAIN:-}"
PANEL_USER="${PANEL_USER:-mnoadmin}"
PANEL_PORT="${PANEL_PORT:-2053}"

ask() { # ask <var> <prompt> <default>
  local __var=$1 __prompt=$2 __default=$3 __answer
  local __current=${!__var:-}
  if [[ -n "$__current" ]]; then return; fi
  read -rp "$__prompt [$__default]: " __answer </dev/tty
  printf -v "$__var" '%s' "${__answer:-$__default}"
}

ask SUB_URL      "Subscription URL to mirror" "$DEFAULT_SUB_URL"
ask DOMAIN       "Panel domain (A record must already point here)" ""
ask EMAIL        "Email for Let's Encrypt" "admin@${DOMAIN:-example.com}"
ask CF_DOMAIN    "Cloudflare-proxied domain (blank to skip)" ""

[[ -n "$DOMAIN" ]] || die "a domain is required"

if [[ -z "${PANEL_PASS:-}" ]]; then
  PANEL_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
fi
PANEL_PATH="$(tr -dc 'a-z0-9' </dev/urandom | head -c 12)"

info "panel:  https://$DOMAIN:$PANEL_PORT/$PANEL_PATH/"
info "user:   $PANEL_USER"

# ---------------------------------------------------------------- swap
# The build peaks well past 1 GB; a small VPS with no swap dies in the linker.
if ! swapon --show | grep -q .; then
  info "adding a 2 GB swapfile"
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi

# ------------------------------------------------------------ toolchain
export DEBIAN_FRONTEND=noninteractive
info "installing build dependencies"
apt-get update -qq
apt-get install -y -qq build-essential curl unzip xz-utils openssl git ca-certificates

if ! command -v go >/dev/null 2>&1; then
  info "installing Go $GO_VERSION"
  curl -fsSL -o /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz
fi
export PATH="/usr/local/go/bin:$PATH"

if ! command -v node >/dev/null 2>&1; then
  info "installing Node $NODE_VERSION"
  curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
  rm -rf /usr/local/node
  mkdir -p /usr/local/node
  tar -xJf /tmp/node.tar.xz -C /usr/local/node --strip-components=1
  ln -sf /usr/local/node/bin/node /usr/local/bin/node
  ln -sf /usr/local/node/bin/npm /usr/local/bin/npm
fi

# ---------------------------------------------------------------- source
if [[ -d "$BUILD_DIR/.git" ]]; then
  info "updating source in $BUILD_DIR"
  git -C "$BUILD_DIR" pull --ff-only
else
  info "cloning into $BUILD_DIR"
  rm -rf "$BUILD_DIR"
  git clone "$REPO_URL" "$BUILD_DIR"
fi

# --------------------------------------------------------------- frontend
info "building the frontend bundle"
export NODE_OPTIONS="--max-old-space-size=1536"
(cd "$BUILD_DIR/frontend" && npm ci --no-audit --no-fund && npm run build)

# ------------------------------------------------------------------- go
# The Go linker writes several hundred MB; /tmp is a small tmpfs on many
# images, so point it at the real disk.
mkdir -p "$GO_TMP"
info "building the panel binary"
(
  cd "$BUILD_DIR"
  TMPDIR="$GO_TMP" CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" \
    go build -ldflags "-w -s" -o build/x-ui main.go
)

# ------------------------------------------------------------- xray core
info "fetching the xray core"
(cd "$BUILD_DIR" && sh ./DockerInit.sh amd64)

# ---------------------------------------------------------------- install
info "installing to $MAIN_FOLDER"
systemctl stop x-ui 2>/dev/null || true
mkdir -p "$MAIN_FOLDER" /etc/x-ui /var/log/x-ui /etc/default
cp "$BUILD_DIR/build/x-ui" "$MAIN_FOLDER/x-ui"
rm -rf "$MAIN_FOLDER/bin"
cp -r "$BUILD_DIR/build/bin" "$MAIN_FOLDER/bin"
cp "$BUILD_DIR/x-ui.sh" "$MAIN_FOLDER/x-ui.sh"
cp -r "$BUILD_DIR/internal/web/translation" "$MAIN_FOLDER/translation"
chmod +x "$MAIN_FOLDER/x-ui" "$MAIN_FOLDER/x-ui.sh" "$MAIN_FOLDER"/bin/*
ln -sf "$MAIN_FOLDER/x-ui.sh" /usr/bin/x-ui

cat >/etc/default/x-ui <<EOF
XUI_DB_FOLDER=/etc/x-ui
XUI_LOG_FOLDER=/var/log/x-ui
XUI_MAIN_FOLDER=$MAIN_FOLDER
EOF

# The unit ships inside the upstream release tarball, not the repo.
if [[ ! -f /etc/systemd/system/x-ui.service ]]; then
  info "installing the systemd unit"
  tmp=$(mktemp -d)
  ver=$(git -C "$BUILD_DIR" describe --tags --abbrev=0 2>/dev/null || echo "v3.10.2")
  curl -fsSL -o "$tmp/rel.tar.gz" \
    "https://github.com/MHSanaei/3x-ui/releases/download/${ver}/x-ui-linux-amd64.tar.gz"
  tar -xzf "$tmp/rel.tar.gz" -C "$tmp" x-ui/x-ui.service.debian
  cp "$tmp/x-ui/x-ui.service.debian" /etc/systemd/system/x-ui.service
  rm -rf "$tmp"
fi

# ------------------------------------------------------------------ cert
# The port-80 inbound and the ACME challenge cannot share port 80, so the
# panel is stopped for the issue and started again after.
if [[ ! -f "/root/cert/$DOMAIN/fullchain.pem" ]]; then
  info "issuing a Let's Encrypt certificate for $DOMAIN"
  [[ -x /root/.acme.sh/acme.sh ]] || curl -fsSL https://get.acme.sh | sh -s "email=$EMAIL"
  systemctl stop x-ui 2>/dev/null || true
  sleep 2
  ss -tlnp | grep -q ':80 ' && die "port 80 is busy; free it and re-run"
  /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --httpport 80 --server letsencrypt
  mkdir -p "/root/cert/$DOMAIN"
  /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
    --key-file "/root/cert/$DOMAIN/privkey.pem" \
    --fullchain-file "/root/cert/$DOMAIN/fullchain.pem" \
    --reloadcmd "systemctl restart x-ui"
else
  info "certificate for $DOMAIN already present"
fi

systemctl daemon-reload
systemctl enable x-ui >/dev/null
systemctl start x-ui
sleep 10
systemctl is-active --quiet x-ui || die "the panel failed to start; see: journalctl -u x-ui -n 50"

# ------------------------------------------------------------------ panel
info "configuring the panel"
"$MAIN_FOLDER/x-ui" setting -username "$PANEL_USER" -password "$PANEL_PASS" >/dev/null
"$MAIN_FOLDER/x-ui" setting -webBasePath "/$PANEL_PATH/" >/dev/null
"$MAIN_FOLDER/x-ui" setting -port "$PANEL_PORT" >/dev/null
systemctl restart x-ui
sleep 10

# Turn the sync on and point it at the subscription + domain. Everything goes
# through the panel's own API so the settings land exactly as the UI writes them.
info "enabling the inbound sync"
BASE_PATH="/$PANEL_PATH"
python3 - "$BASE_PATH" "$PANEL_USER" "$PANEL_PASS" "$SUB_URL" "$DOMAIN" "$CF_DOMAIN" <<'PY'
import json, subprocess, sys
base, user, pw, sub_url, domain, cf_domain = sys.argv[1:7]
root = f"http://127.0.0.1:2053{base}"
jar = "/tmp/xui-install-cookies.txt"

def curl(args):
    return subprocess.run(["curl", "-s", "--max-time", "300"] + args,
                          capture_output=True, text=True).stdout.strip()

tok = json.loads(curl(["-c", jar, f"{root}/csrf-token"]))["obj"]
login = curl(["-b", jar, "-c", jar, "-X", "POST", f"{root}/login",
              "-H", f"X-CSRF-Token: {tok}",
              "-d", f"username={user}&password={pw}"])
if '"success":true' not in login:
    sys.exit(f"panel login failed: {login[:200]}")

tok = json.loads(curl(["-b", jar, "-c", jar, f"{root}/csrf-token"]))["obj"]
settings = json.loads(curl(["-b", jar, "-H", f"X-CSRF-Token: {tok}",
                            "-X", "POST", f"{root}/panel/api/setting/all"]))["obj"]
settings["subInboundSyncEnable"] = True
settings["subInboundSyncUrl"] = sub_url
settings["subInboundSyncDomain"] = domain
settings["subInboundSyncCfDomain"] = cf_domain
settings["subDomain"] = domain
with open("/tmp/xui-install-payload.json", "w") as fh:
    json.dump(settings, fh)

saved = curl(["-b", jar, "-H", f"X-CSRF-Token: {tok}", "-H", "Content-Type: application/json",
              "-X", "POST", f"{root}/panel/api/setting/update",
              "--data-binary", "@/tmp/xui-install-payload.json"])
if '"success":true' not in saved:
    sys.exit(f"saving settings failed: {saved[:200]}")

result = json.loads(curl(["-b", jar, "-H", f"X-CSRF-Token: {tok}",
                          "-X", "POST", f"{root}/panel/api/inbounds/syncSubscription"]))
obj = result.get("obj") or {}
print(f"    added {obj.get('Added')} inbounds, skipped {len(obj.get('Skipped') or [])}")

# The subscription lives at <subPath><subId>; subPath is a random secret.
sub_path = (settings.get("subPath") or "/sub/").strip("/")
sub_port = settings.get("subPort") or 2096
with open("/tmp/xui-install-suburl", "w") as fh:
    fh.write(f"{sub_path}/subsync-all:{sub_port}")
PY

SUB_INFO=$(cat /tmp/xui-install-suburl)

# ------------------------------------------------------------------ done
echo
info "done"
echo
echo "  panel:        https://$DOMAIN:$PANEL_PORT/$PANEL_PATH/"
echo "  username:     $PANEL_USER"
echo "  password:     $PANEL_PASS"
echo "  subscription: https://$DOMAIN/$SUB_INFO"
if [[ -n "$CF_DOMAIN" ]]; then
  echo "  via Cloudflare: https://$CF_DOMAIN (links in the same subscription)"
fi
echo
echo "The sync rebuilds the inbounds every 30 minutes. Point Cloudflare at"
echo "$DOMAIN with the proxy OFF for the direct links, and at $CF_DOMAIN with"
echo "it ON for the proxied ones."
echo
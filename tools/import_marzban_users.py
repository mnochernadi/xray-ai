#!/usr/bin/env python3
"""Bring Marzban users onto an x-ui panel without changing their sub link.

A Marzban user's subscription URL is `<prefix>/sub/<token>`, where the token is
base64url("username,timestamp") followed by the first ten characters of a
SHA-256 over that payload and the panel's subscription secret. The panel
accepts that token (see internal/sub/marzban.go) and resolves it to the
username, so as long as every imported client carries the username as its
sub_id, the user keeps the exact URL they already hold — only the host part
changes.

An x-ui client lives in four places, and all four are written here:

  clients              one row per (user, inbound). `total_gb` holds BYTES in
                       an int64 despite the name; a float there makes Go fail to
                       scan the whole table, which stops Xray from starting.
  client_inbounds      the join row the subscription walks to reach the inbound
  inbounds.settings    the `clients` array the panel renders into the core.
                       Its `totalGB` is bytes as well, and must be an integer.
  client_traffics      the accounting row. Without it the client is reported as
                       unlimited and never expires.

Traffic the user already spent on Marzban is carried over as `up`, so they keep
the quota they had left instead of starting from zero. Every inbound's client
copy carries the user's full limit: x-ui enforces a quota per client, so giving
each inbound a fraction of the limit would cut the user off early.

The panel's `marzbanSubSecret` setting is filled in from the Marzban database's
`jwt.secret_key` — the same secret Marzban signs those tokens with.

Re-running is safe: clients and traffic rows that already exist are left alone.

Read-only against Marzban. Only the x-ui database is written.

    # from a Marzban database file (also picks up the token secret)
    python3 tools/import_marzban_users.py --marzban-db /path/to/db.sqlite3

    # from a running Marzban panel (secret must be supplied)
    python3 tools/import_marzban_users.py --marzban-url https://panel:8000 \\
        --username admin --password secret --sub-secret <64 hex chars>
"""

import argparse
import json
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_XUI_DB = "/etc/x-ui/x-ui.db"

# Marzban account statuses to bring over. "active" is the live set; "limited"
# and "expired" are the accounts Marzban has already suspended.
DEFAULT_STATUSES = ("active",)

CLIENT_COLUMNS = (
    "email, sub_id, uuid, password, auth, flow, security, reverse, "
    "wg_private_key, wg_public_key, wg_allowed_ips, wg_pre_shared_key, "
    "wg_keep_alive, wg_forwarded_ports, secret, ad_tag, limit_ip, limit_hwid, "
    "total_gb, expiry_time, enable, tg_id, group_name, comment, reset, reset_day, "
    "reset_weekday, reset_max, traffic_reset, traffic_reset_day, created_at, "
    "updated_at, sync_orphaned_at"
)
CLIENT_VALUES = "?,?,?,?,?,'','','','','','','',0,'','','',0,0,?,?,1,0,'','',0,0,0,0,'never',1,?,?,0"


def load_from_db(path, statuses):
    """Users with their per-protocol credentials, keyed by username."""
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    marks = ",".join("?" * len(statuses))
    users = {}
    for uid, username, limit, expire, used in con.execute(
        f"select id, username, data_limit, expire, used_traffic from users "
        f"where status in ({marks})",
        statuses,
    ):
        users[uid] = new_user(username, limit, expire, used)
    for uid, ptype, settings in con.execute(
        "select user_id, type, settings from proxies"
    ):
        if uid in users:
            users[uid]["proxies"][ptype.lower()] = json.loads(settings)

    secret = ""
    try:
        row = con.execute("select secret_key from jwt limit 1").fetchone()
        secret = (row[0] if row else "") or ""
    except sqlite3.Error:
        pass  # table absent: an older Marzban layout, or a partial dump
    return list(users.values()), secret


def load_from_api(url, username, password, statuses):
    """Same shape as load_from_db, but read from a running Marzban panel.

    Marzban does not expose the token secret over its API, so it is not
    returned here — pass --sub-secret instead.
    """
    base = url.rstrip("/")
    body = urllib.parse.urlencode({"username": username, "password": password})
    token = request(base + "/api/admin/token", data=body.encode())["access_token"]

    users = []
    offset = 0
    while True:
        query = urllib.parse.urlencode(
            {"offset": offset, "limit": 100, "status": list(statuses)}
        )
        page = request(f"{base}/api/users?{query}", token=token)
        batch = page.get("users") or []
        for raw in batch:
            user = new_user(
                raw.get("username"),
                raw.get("data_limit"),
                raw.get("expire"),
                raw.get("used_traffic"),
            )
            for ptype, settings in (raw.get("proxies") or {}).items():
                if settings:
                    user["proxies"][str(ptype).lower()] = settings
            users.append(user)
        offset += len(batch)
        if not batch or offset >= (page.get("total") or offset):
            break
    return users, ""


def new_user(username, limit, expire, used):
    return {
        "username": username,
        "limit": int(limit or 0),    # bytes; 0 means unlimited
        "expire": int(expire or 0),  # unix seconds; 0 means never
        "used": int(used or 0),      # bytes; carried over as `up`
        "proxies": {},
    }


def request(url, data=None, token=None):
    req = urllib.request.Request(url, data=data)
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as err:
        sys.exit(f"marzban {url}: HTTP {err.code} {err.read().decode()[:200]}")


def credentials(user, proto):
    """The uuid/password/flow triple a given inbound protocol needs."""
    cred = user["proxies"].get(proto)
    if not cred:
        return None
    if proto in ("vless", "vmess"):
        return {"uuid": cred.get("id") or "", "password": "",
                "flow": cred.get("flow") or ""}
    return {"uuid": "", "password": cred.get("password") or "", "flow": ""}


def ensure_traffic(db, seen, inbound_id, email, user, now):
    """Write the accounting row for a client that has none."""
    if email in seen:
        return 0
    db.execute(
        "insert into client_traffics (inbound_id, enable, email, up, down, "
        "expiry_time, total, reset, reset_day, reset_weekday, reset_max, "
        "reset_count, last_online, last_sub_fetch) "
        "values (?,1,?,?,0,?,?,0,0,0,0,0,0,0)",
        (inbound_id, email, user["used"], user["expire"] * 1000, user["limit"]),
    )
    seen.add(email)
    return 1


def set_sub_secret(db, secret):
    if not secret:
        return False
    row = db.execute(
        "select value from settings where key='marzbanSubSecret'"
    ).fetchone()
    if row is None:
        db.execute(
            "insert into settings (key, value) values ('marzbanSubSecret', ?)",
            (secret,),
        )
    elif row[0] != secret:
        db.execute(
            "update settings set value=? where key='marzbanSubSecret'", (secret,)
        )
    else:
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--marzban-db", help="Marzban sqlite file (read-only)")
    source.add_argument("--marzban-url", help="e.g. https://panel:8000")
    parser.add_argument("--username", help="Marzban admin username")
    parser.add_argument("--password", help="Marzban admin password")
    parser.add_argument("--sub-secret", default="",
                        help="Marzban jwt.secret_key; required with --marzban-url")
    parser.add_argument("--xui-db", default=DEFAULT_XUI_DB)
    parser.add_argument("--status", default=",".join(DEFAULT_STATUSES),
                        help="Marzban statuses to import (default: active)")
    args = parser.parse_args()

    statuses = tuple(s.strip() for s in args.status.split(",") if s.strip())
    if args.marzban_db:
        users, secret = load_from_db(args.marzban_db, statuses)
    else:
        if not (args.username and args.password):
            sys.exit("--marzban-url needs --username and --password")
        users, secret = load_from_api(
            args.marzban_url, args.username, args.password, statuses
        )
        secret = args.sub_secret
    print(f"marzban users ({'/'.join(statuses)}): {len(users)}")

    now = int(time.time() * 1000)
    db = sqlite3.connect(args.xui_db)
    db.execute("pragma foreign_keys = on")

    if set_sub_secret(db, secret):
        print("set marzbanSubSecret on the panel")
    elif not secret:
        print("WARNING: no subscription secret set — Marzban tokens will not "
              "resolve until marzbanSubSecret is filled in", file=sys.stderr)

    known_emails = {e[0] for e in db.execute("select email from clients")}
    seen_traffic = {e[0] for e in db.execute("select email from client_traffics")}

    added_clients = added_links = added_traffic = 0

    for iid, port, proto, settings_raw in list(
        db.execute("select id, port, protocol, settings from inbounds")
    ):
        settings = json.loads(settings_raw) if settings_raw else {}
        clients = settings.get("clients") or []

        for user in users:
            cred = credentials(user, proto)
            if cred is None:
                continue
            email = f"{user['username']}-{port}"

            if email in known_emails:
                # Already imported. The accounting row may still be missing if
                # an older run did not write it, so make sure it exists.
                added_traffic += ensure_traffic(
                    db, seen_traffic, iid, email, user, now
                )
                continue

            cur = db.execute(
                f"insert into clients ({CLIENT_COLUMNS}) values ({CLIENT_VALUES})",
                (email, user["username"], cred["uuid"], cred["password"],
                 cred["flow"], user["limit"], user["expire"] * 1000, now, now),
            )
            db.execute(
                "insert into client_inbounds (client_id, inbound_id, "
                "flow_override, created_at) values (?,?,'',?)",
                (cur.lastrowid, iid, now),
            )
            added_clients += 1
            added_links += 1
            added_traffic += ensure_traffic(
                db, seen_traffic, iid, email, user, now
            )

            clients.append({
                "email": email,
                "enable": True,
                "expiryTime": user["expire"] * 1000,
                "totalGB": user["limit"],
                "limitIp": 0,
                "subId": user["username"],
                "id": cred["uuid"],
                "password": cred["password"],
                "flow": cred["flow"],
                "security": "auto" if proto == "vmess" else "",
                "created_at": now,
                "updated_at": now,
            })

        settings["clients"] = clients
        db.execute("update inbounds set settings=? where id=?",
                   (json.dumps(settings, ensure_ascii=False), iid))
        print(f"  inbound {iid:>3} {proto:<12} port={port:<6} clients now "
              f"{len(clients)}")

    db.commit()
    print(f"added {added_clients} clients, {added_links} links, "
          f"{added_traffic} traffic rows")
    print("restart the panel for the core to pick them up: systemctl restart x-ui")


if __name__ == "__main__":
    main()
# Moving users off a Marzban panel

Marzban serves each user's subscription at `<prefix>/sub/<token>`, where the
token is `base64url("username,timestamp")` followed by the first ten characters
of a SHA-256 over that payload and the panel's subscription secret.

This fork accepts that token as a subscription id (`internal/sub/marzban.go`)
and resolves it to the username, so an imported client whose `sub_id` is the
username answers at the **same link the user already has**. Only the host part
of the URL changes — nothing for the user to reconfigure.

Tools:

* `tools/import_marzban_users.py` — copies the users across (four tables).
* `internal/sub/marzban.go` — the token resolver, active when the panel's
  `marzbanSubSecret` setting is set.

## فارسی — خلاصه اجرا

```bash
# ۱. کاربران مرزبان را روی پنل x-ui وارد کن (فقط فعال‌ها؛ بقیه با --status)
python3 tools/import_marzban_users.py --marzban-db /path/to/marzban/db.sqlite3

# اگر فقط بکاپ دیتابیس را داری، همین کافی است.
# اگر پنل مرزبان بالا و در دسترس است:
python3 tools/import_marzban_users.py \
    --marzban-url https://panl.example.ir:8000 \
    --username admin --password ****** \
    --sub-secret <secret_key>

systemctl restart x-ui
```

`secret_key` همان مقدار ستون `secret_key` در جدول `jwt` دیتابیس مرزبان است:

```bash
sqlite3 db.sqlite3 "select secret_key from jwt"
```

اسکریپت خودش این را در تنظیمات پنل (`marzbanSubSecret`) می‌نویسد، پس با
`--marzban-db` هیچ کار دستی لازم نیست. بعد از ری‌استارت، لینک کاربر با همان
رشته قبلی کار می‌کند:

```
قبل:  https://panl.mono-itstheend.ir:2096/sub/TU9OT19WUE4sMTc5MjE0MTE2OAZ-ieTtUlAL
بعد:  https://newpanl.mono-itstheend.ir:2096/sub/TU9OT19WUE4sMTc5MjE0MTE2OAZ-ieTtUlAL
```

## What the import writes

An x-ui client is stored in four places, and all four have to agree:

| where | why |
| --- | --- |
| `clients` | one row per (user, inbound). **`total_gb` holds bytes in an int64** despite the name |
| `client_inbounds` | the join row the subscription walks to reach the inbound |
| `inbounds.settings` → `clients` | the array the panel renders into the core. Its `totalGB` is bytes too |
| `client_traffics` | quota and expiry. Without it the client reports as unlimited and never expires |

Two traps worth knowing, both of which cost real debugging time here:

* **`total_gb` must be an integer.** Writing a float (e.g. `0.1` gigabytes)
  makes Go fail to scan the column — `converting driver.Value type float64 to a
  int64` — which breaks *every* read of the clients table: the subscription
  returns 404 and Xray refuses to start. The column holds **bytes**, not
  gigabytes, despite its name.
* **`client_traffics` is not optional.** A client with no row there is served,
  but reported as unlimited and never expiring, so the user's quota silently
  stops being enforced.

Traffic the user already spent on Marzban is carried over as `up`, so they keep
the quota they had left rather than starting from zero. Every inbound's copy of
the client carries the user's full limit — x-ui enforces a quota per client, so
splitting the limit across inbounds would cut the user off early.

## Behind Cloudflare

If the host is proxied, the subscription and the panel share one external port
(2096) and are separated by an **Origin Rule**. Cloudflare applies the *last*
matching Origin Rule, so the catch-all has to come first:

```
route  http.host eq "newpanl.example.ir" and not starts_with(http.request.uri.path, "/sub/")  -> 2053  (panel)
route  http.host eq "newpanl.example.ir" and starts_with(http.request.uri.path, "/sub/")      -> 2096  (subscription)
```

Reversed, every `/sub/` request lands on the panel and answers 404.

## Notes

* Only `active` accounts are imported by default; `--status active,limited` adds
  accounts Marzban has suspended for quota.
* The script only ever reads the Marzban database.
* Re-running is safe: clients and traffic rows that already exist are left
  alone, and only missing accounting rows are filled in.
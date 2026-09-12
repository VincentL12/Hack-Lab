# Cyber Range Lab: "Cookie Reuse & MFA Bypass"

---

## 1. Architecture

```
cyber-range-lab/
├── app/                  # Vulnerable Node.js/Express app
│   ├── server.js
│   ├── public/           # index.html (feedback form), login.html
│   ├── package.json
│   └── Dockerfile
├── logs-seed/
│   └── seed_logs.py      # Injects the simulated attack sequence
├── scripts/
│   └── provision.sh      # Host VM setup: Docker, log dir, Blue Team SSH
└── docker-compose.yml
```

- **Web app**: HTTP on port `3075` (Node.js/Express, containerized)
- **Blue Team SSH**: port `2275`, user `analyst` / `blue_team_rocks`
- **Logs**: `/opt/admin/logs/{access.log,error.log}` on the host, bind-mounted
  into the app container so both the running app and the Blue Team's SSH
  session see the same files.
- **Deployment target**: a single Linux VM (intended for a Proxmox guest),
  everything else runs via Docker Compose inside it.

## 2. Deployment (on a fresh Proxmox VM)

```bash
git clone <this-repo> cyber-range-lab
cd cyber-range-lab

# 1) One-time host setup: installs Docker, creates /opt/admin/logs,
#    creates the analyst SSH user on port 2275
sudo ./scripts/provision.sh

# 2) Build and start the lab (also seeds the mock attack logs)
docker compose up -d --build

# 3) Confirm it's up
curl -i http://localhost:3075/
ssh analyst@<vm-ip> -p 2275   # password: blue_team_rocks
```

Place the VM in an internal network zone (e.g. `feedback.admin.local`) per
the scenario brief — no public exposure needed or wanted.

## 3. Red Team walkthrough (live demo)

The exploit chain is meant to be demonstrated live in two real browser tabs
(as called for in the presentation), not fully automated — that's also more
convincing to watch than a script.

**Tab A — you, as the "victim admin":**
1. Go to `http://<host>:3075/login`, sign in with `admin` /
   `FeedbackAdm1n!2025`.
2. Enter the MFA code shown on screen (`482913` by default).
3. You land on `/dashboard`, now holding a real `adm_sess` cookie.

**Tab B — you, as the attacker, in a separate/incognito session:**
1. `curl http://<host>:3075/robots.txt` — discloses `/api/verify-mfa` and
   `/dashboard` as "restricted", and `X-Powered-By: Node.js` confirms the
   stack. View page source on `/` for the ASCII-art hint pointing at
   `robots.txt`.
2. Try a `<script>` XSS payload against `POST /api/feedback` — the WAF
   returns `403`.
3. Bypass it with an SVG vector, targeting the admin's non-HttpOnly cookie
   and exfiltrating to the built-in collector:
   ```html
   <svg onload="fetch('/collect?c='+window['docu'+'ment']['coo'+'kie'])">
   ```
4. In **Tab A**, visit `/admin/review` as the logged-in admin — the stored
   payload fires in the admin's real browser and exfiltrates their cookies
   to `/collect`.
5. Back in **Tab B**, check `GET /collected` to retrieve the stolen
   `adm_sess` value.
6. Set that value as your own `adm_sess` cookie (dev tools, or
   `curl --cookie "adm_sess=<stolen>"`) and hit `/dashboard` directly —
   **no login, no MFA code, ever** — and get the flag:
   `SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}`.

The root cause: `/dashboard` trusts any known `adm_sess` token by itself. It
never re-checks that `/api/verify-mfa` was hit for *this* request, and the
cookie isn't bound to an IP, device, or session freshness window — so a
stolen cookie is just as good as a real login.

## 4. Blue Team walkthrough (log forensics)

SSH in as the analyst and inspect the seeded narrative:

```bash
ssh analyst@<vm-ip> -p 2275
tail -f /opt/admin/logs/access.log /opt/admin/logs/error.log
```

Reading `access.log`, you can reconstruct:
- Legitimate baseline traffic from `192.168.1.100` (normal admin usage)
- Recon from `10.10.14.50` (`Mozilla/5.0` UA): `/`, `/robots.txt`,
  a `401` on `/dashboard`
- A blocked `<script>` WAF hit at `18:50:15`, immediately followed by a
  successful `POST /api/feedback` (the SVG bypass)
- A `200` on `/dashboard` at `18:51:55` from the same attacker IP — with an
  oddly long `X-Forwarded-For` value. That's the attacker's OPSEC slip:
  decode it as Base64 (44+ chars, `=` padding is your first clue) and you
  get the final Blue Team flag.
- Grep for `never` and `/api/verify-mfa`: the attacker's IP appears nowhere
  against that endpoint — proof MFA was never re-checked for this session.

`error.log` carries the `WARN`/`CRITICAL` trail, including two `CRITICAL`
entries flagging the cookie-reuse and "Authentication bypass anomaly."

## 5. Notes

-if you cannot connect to ssh at port 2275 you can use this fix

```bash
sudo systemctl edit ssh.socket --full
add ListenStream=2275 
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
```

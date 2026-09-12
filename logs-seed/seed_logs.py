#!/usr/bin/env python3
"""
seed_logs.py
Injects a simulated attack sequence into /opt/admin/logs/{access,error}.log
on container startup, so the Blue Team has a realistic forensic trail to
analyze even before anyone touches the app live.

Run once at container start (see docker-compose.yml). Idempotent: skips
seeding if the marker line is already present.
"""

import os
from datetime import datetime, timedelta, timezone

LOG_DIR = os.environ.get("LOG_DIR", "/opt/admin/logs")
ACCESS_LOG = os.path.join(LOG_DIR, "access.log")
ERROR_LOG = os.path.join(LOG_DIR, "error.log")

MARKER = "# seeded-by-seed_logs.py"

# Self-consistent exfiltration flag.
# NOTE: the original assignment brief's sample Base64 string
# ("UEhBTlRPTUdSSUR7QkxVRV9NMGdfSHVudDNyX000c3Qzcn0")
# does not actually decode to the flag the brief claims, and its length
# doesn't match the stated 44 characters either — it decodes to
# "PHANTOMGRID{BLUE_L0g_Hunt3r_M4st3r}", which looks like a leftover
# from a template this brief was copy-pasted from. This script uses a
# corrected, verified value instead (see README "Assumptions" section).
BLUE_FLAG_PLAINTEXT = "SCENARIO75{BLUE_L0G_HUnt3r_M4st3r}"
import base64
XFF_B64 = base64.b64encode(BLUE_FLAG_PLAINTEXT.encode()).decode()

ATTACKER_IP = "10.10.14.50"
ATTACKER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"
LEGIT_IP = "192.168.1.100"


def ts(base_date, hh, mm, ss):
    return base_date.replace(hour=hh, minute=mm, second=ss).strftime("%d/%b/%Y:%H:%M:%S +0000")


def iso_ts(base_date, hh, mm, ss):
    return base_date.replace(hour=hh, minute=mm, second=ss).isoformat() + "Z"


def already_seeded():
    if not os.path.exists(ACCESS_LOG):
        return False
    with open(ACCESS_LOG) as f:
        return MARKER in f.read()


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    if already_seeded():
        print("[seed_logs] Logs already seeded, skipping.")
        return

    today = datetime.now(timezone.utc)

    access_lines = [f"{MARKER}\n"]
    error_lines = [f"{MARKER}\n"]

    # --- Baseline legitimate admin traffic (noise for Threat Hunting) ---
    for hh, mm, ss in [(18, 40, 2), (18, 42, 47), (18, 45, 30), (18, 49, 11)]:
        access_lines.append(
            f'{LEGIT_IP} - - [{ts(today, hh, mm, ss)}] "GET /dashboard HTTP/1.1" 200 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n'
        )

    # --- PHASE 1: Reconnaissance from attacker ---
    access_lines.append(
        f'{ATTACKER_IP} - - [{ts(today, 18, 49, 40)}] "GET / HTTP/1.1" 200 "-" "{ATTACKER_UA}"\n'
    )
    access_lines.append(
        f'{ATTACKER_IP} - - [{ts(today, 18, 49, 48)}] "GET /robots.txt HTTP/1.1" 200 "-" "{ATTACKER_UA}"\n'
    )
    access_lines.append(
        f'{ATTACKER_IP} - - [{ts(today, 18, 49, 55)}] "GET /dashboard HTTP/1.1" 401 "-" "{ATTACKER_UA}"\n'
    )

    # --- PHASE 2: WAF block, then bypass ---
    error_lines.append(
        f"[{iso_ts(today, 18, 50, 15)}] [WARN] WAF blocked <script> payload from {ATTACKER_IP}\n"
    )
    access_lines.append(
        f'{ATTACKER_IP} - - [{ts(today, 18, 50, 15)}] "POST /api/feedback HTTP/1.1" 403 "-" "{ATTACKER_UA}"\n'
    )
    access_lines.append(
        f'{ATTACKER_IP} - - [{ts(today, 18, 50, 42)}] "POST /api/feedback HTTP/1.1" 200 "-" "{ATTACKER_UA}"\n'
    )

    # --- PHASE 3: Stolen cookie replay straight to /dashboard, MFA never hit ---
    # Attacker's sloppy OPSEC: stashes the stolen (base64'd) session data in
    # its own X-Forwarded-For header. Great catch for a sharp analyst.
    access_lines.append(
        f'{ATTACKER_IP} - - [{ts(today, 18, 51, 55)}] "GET /dashboard HTTP/1.1" 200 "{XFF_B64}" "{ATTACKER_UA}"\n'
    )

    error_lines.append(
        f"[{iso_ts(today, 18, 51, 56)}] [CRITICAL] Cookie reuse detected: adm_sess token observed from new source IP "
        f"{ATTACKER_IP} without a preceding /api/verify-mfa call in this session's history.\n"
    )
    error_lines.append(
        f"[{iso_ts(today, 18, 53, 10)}] [CRITICAL] Authentication bypass anomaly: /dashboard granted access via "
        f"replayed adm_sess cookie; /api/verify-mfa was never invoked for this session.\n"
    )

    with open(ACCESS_LOG, "a") as f:
        f.writelines(access_lines)
    with open(ERROR_LOG, "a") as f:
        f.writelines(error_lines)

    print(f"[seed_logs] Seeded {len(access_lines)} access.log lines and {len(error_lines)} error.log lines.")
    print(f"[seed_logs] X-Forwarded-For exfil string (Base64, {len(XFF_B64)} chars): {XFF_B64}")
    print(f"[seed_logs] Decodes to: {BLUE_FLAG_PLAINTEXT}")


if __name__ == "__main__":
    main()

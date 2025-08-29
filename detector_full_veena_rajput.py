#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Real-time PII Defense - Detector & Redactor
Candidate: Veena Rajput

Usage:
    python3 detector_full_veena_rajput.py iscp_pii_dataset.csv

Input CSV columns: record_id, Data_json (JSON string)
Output CSV columns: record_id, redacted_data_json, is_pii
"""

import sys
import csv
import json
import re

# ---------- Regexes & Helpers ----------

RE_PHONE_10 = re.compile(r'\b[6-9]\d{9}\b')  # Indian 10-digit mobile numbers typically start 6-9
RE_AADHAAR_12 = re.compile(r'\b\d{12}\b')
# Indian passport: 1 letter + 7 digits (most common); accept optional second letter as some series use it
RE_PASSPORT = re.compile(r'\b([A-Z]{1,2}\d{7})\b', re.IGNORECASE)
# UPI: username@psp (username: alnum . _ -; psp typically letters) or 10-digit@psp
RE_UPI = re.compile(r'\b([a-zA-Z0-9._-]{2,}|[6-9]\d{9})@[a-zA-Z]{2,}\b')

EMAIL_RE = re.compile(r'\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')
IPV4_RE = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')

def mask_phone(v: str) -> str:
    m = RE_PHONE_10.search(v)
    if not m: 
        return v
    s = m.group(0)
    return v.replace(s, s[:2] + "XXXXXX" + s[-2:])

def mask_aadhaar(v: str) -> str:
    m = RE_AADHAAR_12.search(v)
    if not m: 
        return v
    s = m.group(0)
    return v.replace(s, f"{s[:4]} XXXX XXXX")

def mask_passport(v: str) -> str:
    m = RE_PASSPORT.search(v)
    if not m:
        return v
    s = m.group(0)
    # keep first char(s), mask digits except last 2
    prefix = re.match(r'[A-Za-z]{1,2}', s).group(0)
    digits = s[len(prefix):]
    masked = prefix.upper() + "XXXXX" + digits[-2:]
    return v.replace(s, masked)

def mask_upi(v: str) -> str:
    m = RE_UPI.search(v)
    if not m:
        return v
    s = m.group(0)
    user_psp = s.split("@")
    user = user_psp[0]
    psp = user_psp[1]
    if len(user) <= 2:
        masked_user = user[0] + "XXX"
    else:
        masked_user = user[:2] + "XXX"
    return v.replace(s, f"{masked_user}@{psp}")

def mask_email(v: str) -> str:
    def _mask(m):
        local, domain = m.group(1), m.group(2)
        if len(local) <= 2:
            masked_local = local[0] + "XXX"
        else:
            masked_local = local[:2] + "XXX"
        return masked_local + "@" + domain
    return EMAIL_RE.sub(_mask, v)

def mask_name(v: str) -> str:
    # Mask each token: keep first letter, replace rest with X
    parts = re.split(r'\s+', v.strip())
    masked = []
    for p in parts:
        if len(p) == 0: 
            continue
        masked.append(p[0] + "XXX" if len(p) > 1 else p[0])
    return " ".join(masked)

def mask_ip(v: str) -> str:
    def _mask(m):
        octets = m.group(1).split(".")
        return f"{octets[0]}.***.***.***"
    return IPV4_RE.sub(_mask, v)

def is_full_name(name_str: str) -> bool:
    # consider full if contains at least two alphabetic tokens
    tokens = [t for t in re.split(r'\s+', name_str.strip()) if t.isalpha()]
    return len(tokens) >= 2

# ---------- Core logic per record ----------

def detect_and_redact(d: dict) -> (dict, bool):
    """
    Returns (redacted_dict, is_pii_bool)
    """
    red = dict(d)  # shallow copy
    pii_present = False

    # Normalize keys (dataset uses known keys)
    keys = set(k.lower() for k in d.keys())

    # --- Standalone PII checks ---
    # phone
    for k in ["phone", "contact"]:
        if k in keys and isinstance(d.get(k), str):
            if RE_PHONE_10.search(d[k]):
                pii_present = True
                red[k] = mask_phone(d[k])

    # Aadhaar
    for k in ["aadhar", "aadhaar"]:
        if k in keys and isinstance(d.get(k), str):
            if RE_AADHAAR_12.search(d[k]):
                pii_present = True
                red[k] = mask_aadhaar(d[k])

    # Passport
    if "passport" in keys and isinstance(d.get("passport"), str):
        if RE_PASSPORT.search(d["passport"]):
            pii_present = True
            red["passport"] = mask_passport(d["passport"])

    # UPI
    if "upi_id" in keys and isinstance(d.get("upi_id"), str):
        if RE_UPI.search(d["upi_id"]):
            pii_present = True
            red["upi_id"] = mask_upi(d["upi_id"])

    # --- Combinatorial PII checks (need >=2 in same record) ---
    combinatorial_flags = 0
    # full name check: from 'name' OR both first_name & last_name
    name_present = False
    if "name" in keys and isinstance(d.get("name"), str) and is_full_name(d["name"]):
        name_present = True
    elif "first_name" in keys and "last_name" in keys and all(isinstance(d.get(x), str) and len(d.get(x,"").strip())>0 for x in ("first_name","last_name")):
        name_present = True
    if name_present:
        combinatorial_flags += 1

    email_present = ("email" in keys and isinstance(d.get("email"), str) and EMAIL_RE.search(d["email"]) is not None)
    if email_present:
        combinatorial_flags += 1

    address_present = ("address" in keys and isinstance(d.get("address"), str) and len(d.get("address").strip())>0)
    if address_present:
        combinatorial_flags += 1

    device_or_ip_present = (
        ("device_id" in keys and isinstance(d.get("device_id"), str) and len(d.get("device_id").strip())>0) or
        ("ip_address" in keys and isinstance(d.get("ip_address"), str) and IPV4_RE.search(d["ip_address"]) is not None)
    )
    if device_or_ip_present:
        combinatorial_flags += 1

    if combinatorial_flags >= 2:
        pii_present = True
        # Redact combinatorial fields that exist
        if "name" in keys and isinstance(d.get("name"), str) and len(d["name"].strip())>0:
            red["name"] = mask_name(d["name"])
        if "first_name" in keys and isinstance(d.get("first_name"), str) and len(d["first_name"].strip())>0:
            # Don't mask single first/last if alone, but since pair present, mask both if exist
            red["first_name"] = d["first_name"][0] + "XXX" if len(d["first_name"])>1 else d["first_name"]
        if "last_name" in keys and isinstance(d.get("last_name"), str) and len(d["last_name"].strip())>0:
            red["last_name"] = d["last_name"][0] + "XXX" if len(d["last_name"])>1 else d["last_name"]
        if email_present:
            red["email"] = mask_email(d.get("email",""))
        if address_present:
            red["address"] = "[REDACTED_PII]"
        if "ip_address" in keys and isinstance(d.get("ip_address"), str) and len(d["ip_address"].strip())>0:
            red["ip_address"] = mask_ip(d["ip_address"])
        if "device_id" in keys and isinstance(d.get("device_id"), str) and len(d["device_id"].strip())>0:
            # keep last 4
            v = d["device_id"]
            red["device_id"] = f"[DEVICE-***{v[-4:]}]"

    return red, bool(pii_present)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_veena_rajput.py iscp_pii_dataset.csv")
        sys.exit(1)
    in_path = sys.argv[1]

    with open(in_path, newline='', encoding='utf-8') as f, \
         open("redacted_output_veena_rajput.csv", "w", newline='', encoding='utf-8') as out:
        reader = csv.DictReader(f)
        fieldnames = ["record_id", "redacted_data_json", "is_pii"]
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            rid = row.get("record_id")
            data_json = row.get("Data_json") or row.get("data_json") or "{}"
            try:
                data = json.loads(data_json)
            except Exception:
                # Try to fix common CSV-escaped JSON quotes
                try:
                    data = json.loads(data_json.replace("''","\"").replace("'", '"'))
                except Exception:
                    data = {}

            red, is_pii = detect_and_redact(data)
            writer.writerow({
                "record_id": rid,
                "redacted_data_json": json.dumps(red, ensure_ascii=False),
                "is_pii": str(bool(is_pii))
            })

if __name__ == "__main__":
    main()

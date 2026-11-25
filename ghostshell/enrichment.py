"""Attacker IP enrichment — GeoIP + ASN, no API key needed.

Uses ip-api.com (free, no key, 45 req/min). Private / localhost IPs
return a local placeholder without a network call. Results are
cached in SQLite so the same IP is looked up once.
"""
import ipaddress
import sqlite3

import requests


def enrich_ip(db_path, ip):
    try:
        if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
            return {"country": "Local / lab", "city": "-", "asn": "-", "org": "localhost"}
    except ValueError:
        return {"country": "?", "city": "-", "asn": "-", "org": "?"}

    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ip_intel "
        "(ip TEXT PRIMARY KEY, country TEXT, city TEXT, asn TEXT, org TEXT)"
    )
    row = conn.execute("SELECT country, city, asn, org FROM ip_intel WHERE ip=?", (ip,)).fetchone()
    if row:
        conn.close()
        return {"country": row[0], "city": row[1], "asn": row[2], "org": row[3]}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,as,org", timeout=3)
        data = r.json()
        if data.get("status") == "success":
            result = {
                "country": data.get("country", "?"),
                "city": data.get("city", "-"),
                "asn": data.get("as", "-"),
                "org": data.get("org", "-"),
            }
        else:
            result = {"country": "?", "city": "-", "asn": "-", "org": "?"}
    except Exception:
        result = {"country": "?", "city": "-", "asn": "-", "org": "?"}
    conn.execute(
        "INSERT OR REPLACE INTO ip_intel VALUES (?,?,?,?,?)",
        (ip, result["country"], result["city"], result["asn"], result["org"]),
    )
    conn.commit()
    conn.close()
    return result


def get_intel(db_path, ip):
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT country, city, asn, org FROM ip_intel WHERE ip=?", (ip,)
        ).fetchone()
    except Exception:
        row = None
    conn.close()
    if row:
        return {"country": row[0], "city": row[1], "asn": row[2], "org": row[3]}
    return {"country": "-", "city": "-", "asn": "-", "org": "-"}

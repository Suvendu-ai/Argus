# core/geoip.py
# ─────────────────────────────────────────
# ARGUS — Geo-IP Location Lookup
# Maps attacker IPs to countries/cities
# Uses ip-api.com (free, no key needed)
# ─────────────────────────────────────────

import requests
import logging
import time
from functools import lru_cache

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ARGUS] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

GEO_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,lat,lon,isp,org,as,query"

# IPs to skip geo lookup
SKIP_IPS = {
    "127.0.0.1", "localhost", "0.0.0.0",
    "Unknown", "", "::1"
}


@lru_cache(maxsize=1000)
def lookup_ip(ip: str) -> dict:
    """
    Looks up geographic location of an IP.
    Results are cached so same IP isn't looked up twice.

    Returns dict with:
    - country, city, lat, lon
    - isp (internet service provider)
    - flag emoji
    """
    # Skip private/local IPs
    if ip in SKIP_IPS:
        return _unknown_location(ip)

    if (ip.startswith("192.168.") or
        ip.startswith("10.")      or
        ip.startswith("172.16.")  or
        ip.startswith("127.")):
        return _local_location(ip)

    try:
        response = requests.get(
            GEO_API_URL.format(ip=ip),
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()

            if data.get("status") == "success":
                return {
                    "ip"           : ip,
                    "country"      : data.get("country",     "Unknown"),
                    "country_code" : data.get("countryCode", "XX"),
                    "region"       : data.get("regionName",  "Unknown"),
                    "city"         : data.get("city",        "Unknown"),
                    "lat"          : data.get("lat",          0.0),
                    "lon"          : data.get("lon",          0.0),
                    "isp"          : data.get("isp",         "Unknown"),
                    "org"          : data.get("org",         "Unknown"),
                    "flag"         : _get_flag(data.get("countryCode", "XX")),
                    "found"        : True
                }

    except requests.exceptions.Timeout:
        logger.warning(f"Geo-IP timeout for {ip}")
    except Exception as e:
        logger.warning(f"Geo-IP error for {ip}: {e}")

    return _unknown_location(ip)


def lookup_batch(ips: list) -> dict:
    """
    Looks up multiple IPs.
    Adds small delay to respect API rate limits.
    Returns dict of ip → location data.
    """
    results = {}
    for ip in set(ips):
        results[ip] = lookup_ip(ip)
        time.sleep(0.1)    # Respect rate limit (45 req/min)
    return results


def enrich_threat(threat: dict) -> dict:
    """
    Adds geo location data to a threat dict.
    Called after threat is detected.
    """
    src_ip = threat.get("src_ip", "Unknown")
    geo    = lookup_ip(src_ip)

    threat["geo"] = geo
    threat["country"]      = geo.get("country",      "Unknown")
    threat["country_code"] = geo.get("country_code", "XX")
    threat["city"]         = geo.get("city",         "Unknown")
    threat["lat"]          = geo.get("lat",           0.0)
    threat["lon"]          = geo.get("lon",           0.0)
    threat["isp"]          = geo.get("isp",          "Unknown")
    threat["flag"]         = geo.get("flag",         "🌐")

    return threat


def _get_flag(country_code: str) -> str:
    """
    Converts country code to flag emoji.
    e.g. "US" → "🇺🇸", "CN" → "🇨🇳"
    """
    if not country_code or len(country_code) != 2:
        return "🌐"
    try:
        return "".join(
            chr(0x1F1E6 + ord(c) - ord('A'))
            for c in country_code.upper()
        )
    except Exception:
        return "🌐"


def _unknown_location(ip: str) -> dict:
    return {
        "ip"           : ip,
        "country"      : "Unknown",
        "country_code" : "XX",
        "region"       : "Unknown",
        "city"         : "Unknown",
        "lat"          : 0.0,
        "lon"          : 0.0,
        "isp"          : "Unknown",
        "org"          : "Unknown",
        "flag"         : "🌐",
        "found"        : False
    }


def _local_location(ip: str) -> dict:
    return {
        "ip"           : ip,
        "country"      : "Local Network",
        "country_code" : "LN",
        "region"       : "LAN",
        "city"         : "Local",
        "lat"          : 0.0,
        "lon"          : 0.0,
        "isp"          : "Local Network",
        "org"          : "Local Network",
        "flag"         : "🏠",
        "found"        : True
    }


# ─────────────────────────────────────────
# Test
# ─────────────────────────────────────────
if __name__ == "__main__":
    test_ips = [
        "8.8.8.8",          # Google USA
        "185.220.101.45",   # Known Tor exit node
        "114.114.114.114",  # China DNS
        "1.1.1.1",          # Cloudflare
        "192.168.1.1",      # Local
    ]

    print("\n" + "═" * 60)
    print("  ARGUS — Geo-IP Lookup Test")
    print("═" * 60)

    for ip in test_ips:
        result = lookup_ip(ip)
        print(f"\n  IP      : {ip}")
        print(f"  Flag    : {result['flag']}")
        print(f"  Country : {result['country']}")
        print(f"  City    : {result['city']}")
        print(f"  ISP     : {result['isp']}")
        print(f"  Coords  : {result['lat']}, {result['lon']}")
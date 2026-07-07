#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("[!] Dependencie Identified:  pip install requests")

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
VIRUSTOTAL_API = "https://www.virustotal.com/api/v3/"
TIMEOUT = 30
VERSION = "2.0"

ENTROPY_THRESHOLD = 6.5

EMPTY_STATUSES = {
    "no_result", "no_results", "hash_not_found", "tag_not_found",
    "signature_not_found", "yara_not_found", "file_not_found",
}


def err(msg):
    print(f"[!] {msg}", file=sys.stderr)


def info(msg):
    print(f"[*] {msg}", file=sys.stderr)


def hr():
    print("-" * 72)

def resolve_auth_key(cli_key, service):
    if cli_key:
        return cli_key
    specific = {
        "threatfox": "THREATFOX_AUTH_KEY",
        "malwarebazaar": "MALWAREBAZAAR_AUTH_KEY",
    }[service]
    key = os.environ.get(specific) or os.environ.get("ABUSECH_AUTH_KEY")
    if not key:
        sys.exit(
            "[!] Auth-Key not found.\n"
            "   pass the --auth-key flag with your key"
        )
    return key


def resolve_vt_key(cli_key):
    if cli_key:
        return cli_key
    sys.exit(
        "[!] VirusTotal API Key not found.\n"
        "   pass the --vt-api-key flag with your key"
    )


def call_threatfox(payload, auth_key):
    headers = {"Auth-Key": auth_key}
    try:
        r = requests.post(THREATFOX_API, json=payload, headers=headers,
                          timeout=TIMEOUT)
    except requests.RequestException as e:
        sys.exit(f"[!] Network Failed (ThreatFox): {e}")
    return _parse_response(r, "ThreatFox")


def call_malwarebazaar(data, auth_key):
    headers = {"Auth-Key": auth_key}
    try:
        r = requests.post(MALWAREBAZAAR_API, data=data, headers=headers,
                          timeout=TIMEOUT)
    except requests.RequestException as e:
        sys.exit(f"[!] Network Failed (MalwareBazaar): {e}")
    return _parse_response(r, "MalwareBazaar")


def call_virustotal(endpoint, api_key):
    """GET on the VirusTotal v3 API. Returns parsed JSON or None on 404."""
    headers = {"accept": "application/json", "x-apikey": api_key}
    url = VIRUSTOTAL_API + endpoint
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
    except requests.RequestException as e:
        sys.exit(f"[!] Network Failed (VirusTotal): {e}")
    if r.status_code in (401, 403):
        sys.exit(f"[!] VirusTotal: Not authorized (HTTP {r.status_code}). "
                 "Verify your API Key at https://www.virustotal.com/")
    if r.status_code == 404:
        return None
    if r.status_code == 429:
        sys.exit("[!] VirusTotal: Quota exceeded (HTTP 429). "
                 "Wait or use a key with higher limits.")
    if r.status_code != 200:
        sys.exit(f"[!] VirusTotal: HTTP {r.status_code} -> {r.text[:300]}")
    try:
        return r.json()
    except ValueError:
        sys.exit("[!] VirusTotal: The response is not a valid JSON.")


def _parse_response(resp, source):
    if resp.status_code in (401, 403):
        sys.exit(f"[!] {source}: Not authorized (HTTP {resp.status_code}). "
                 "Verify your Auth-Key em https://auth.abuse.ch/")
    if resp.status_code != 200:
        sys.exit(f"[!] {source}: HTTP {resp.status_code} -> {resp.text[:300]}")
    try:
        return resp.json()
    except ValueError:
        sys.exit(f"[!] {source}: The response is not a valid JSON.")


def get_data(resp):
    status = resp.get("query_status", "ok")
    if status in EMPTY_STATUSES:
        return []
    if status != "ok":
        err(f"query_status='{status}' "
            f"({resp.get('data') or 'no aditional details'})")
        return []
    data = resp.get("data", resp)
    if isinstance(data, dict):
        return [data]
    return data or []

def print_threatfox_iocs(items):
    if not items:
        print("None IOC was found on ThreatFox.")
        return
    print(f"ThreatFox: {len(items)} IOC Founded\n")
    for it in items:
        hr()
        print(f"  IOC          : {it.get('ioc')}")
        print(f"  Type         : {it.get('ioc_type')} "
              f"({it.get('threat_type')})")
        print(f"  Malware      : {it.get('malware_printable')} "
              f"[{it.get('malware')}]")
        if it.get("malware_alias"):
            print(f"  Aliases      : {it.get('malware_alias')}")
        print(f"  Confidence    : {it.get('confidence_level')}%")
        print(f"  First Seen    : {it.get('first_seen')}")
        if it.get("last_seen"):
            print(f"  Last Seen: {it.get('last_seen')}")
        if it.get("tags"):
            print(f"  Tags         : {', '.join(it['tags'])}")
        if it.get("malware_malpedia"):
            print(f"  Malpedia     : {it.get('malware_malpedia')}")
        if it.get("reference"):
            print(f"  Reference   : {it.get('reference')}")
        samples = it.get("malware_samples") or []
        if samples:
            print(f"  Associated Samples ({len(samples)}):")
            for s in samples[:10]:
                print(f"     - {s.get('sha256_hash')} "
                      f"(MalwareBazaar: {bool(s.get('malware_bazaar'))})")
            if len(samples) > 10:
                print(f"     ... +{len(samples) - 10} amostra(s)")
    hr()


def print_mb_full_info(sample):
    s = sample
    hr()
    print(f"  Filename      : {s.get('file_name')}")
    print(f"  SHA256       : {s.get('sha256_hash')}")
    print(f"  SHA1         : {s.get('sha1_hash')}")
    print(f"  MD5          : {s.get('md5_hash')}")
    print(f"  File Size      : {s.get('file_size')} bytes")
    print(f"  Type         : {s.get('file_type')} "
          f"({s.get('file_type_mime')})")
    print(f"  Signature      : {s.get('signature') or 'N/D'}")
    print(f"  First Seen   : {s.get('first_seen')}")
    print(f"  Last Seen  : {s.get('last_seen')}")
    print(f"  Reporter     : {s.get('reporter')} "
          f"(Origin Country: {s.get('origin_country', 'N/D')})")
    if s.get("imphash"):
        print(f"  Imphash      : {s.get('imphash')}")
    if s.get("tlsh"):
        print(f"  TLSH         : {s.get('tlsh')}")
    if s.get("ssdeep"):
        print(f"  ssdeep       : {s.get('ssdeep')}")
    if s.get("telfhash"):
        print(f"  telfhash     : {s.get('telfhash')}")
    if s.get("gimphash"):
        print(f"  gimphash     : {s.get('gimphash')}")
    if s.get("dhash_icon"):
        print(f"  dhash_icon   : {s.get('dhash_icon')}")
    if s.get("tags"):
        print(f"  Tags         : {', '.join(s['tags'])}")

    cs = s.get("code_sign")
    if cs:
        entry = cs[0] if isinstance(cs, list) and cs else cs
        if isinstance(entry, dict):
            print("  Code signing :")
            print(f"     Subject CN : {entry.get('subject_cn')}")
            print(f"     Issuer  CN : {entry.get('issuer_cn')}")
            print(f"     Serial     : {entry.get('serial_number')}")

    yara = s.get("yara_rules") or []
    if yara:
        print(f"  YARA Rules ({len(yara)}):")
        for y in yara:
            print(f"     - {y.get('rule_name')} (autor: {y.get('author')})")

    vi = s.get("vendor_intel") or {}
    if vi:
        print(f"  Intelligence Vendor : {', '.join(sorted(vi.keys()))}")
    hr()


def print_mb_samples(items):
    if not items:
        print("None sample was found on MalwareBazaar.")
        return
    print(f"MalwareBazaar: {len(items)} Founded Samples:\n")
    for s in items:
        hr()
        print(f"  SHA256   : {s.get('sha256_hash')}")
        print(f"  Filename  : {s.get('file_name')}  "
              f"({s.get('file_type')}, {s.get('file_size')} bytes)")
        print(f"  Signature  : {s.get('signature') or 'N/D'}")
        print(f"  First Seen : {s.get('first_seen')}")
        if s.get("imphash"):
            print(f"  imphash  : {s.get('imphash')}")
        if s.get("tags"):
            print(f"  Tags     : {', '.join(s['tags'])}")
    hr()


def print_vt_ip(ip, resp):
    """Pretty-print a VirusTotal IP address report (clean style)."""
    if not resp:
        print("IP address unknown on VirusTotal.")
        return
    attr = (resp.get("data") or {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    hr()
    print(f"  IP            : {ip}")
    if attr.get("as_owner"):
        print(f"  AS Owner      : {attr.get('as_owner')} "
              f"(ASN {attr.get('asn', 'N/D')})")
    if attr.get("country"):
        print(f"  Country       : {attr.get('country')}")
    if attr.get("network"):
        print(f"  Network       : {attr.get('network')}")
    if attr.get("reputation") is not None:
        print(f"  Reputation    : {attr.get('reputation')}")
    print("  Analysis Stats:")
    print(f"     [!] Malicious  : {stats.get('malicious', 0)}")
    print(f"     [!] Suspicious : {stats.get('suspicious', 0)}")
    print(f"     [+] Harmless   : {stats.get('harmless', 0)}")
    print(f"     [-] Undetected : {stats.get('undetected', 0)}")
    tags = attr.get("tags") or []
    if tags:
        print(f"  Tags          : {', '.join(tags)}")
    hr()


def print_vt_hash(sample_hash, resp, vendor_name=None):
    """Pretty-print a VirusTotal file report / binary triage (clean style)."""
    if not resp:
        print("Hash unknown on VirusTotal.")
        return
    attr = (resp.get("data") or {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    pe = attr.get("pe_info", {}) or {}

    hr()
    print("  ==== Artifact General Information ====")
    print(f"  Hash          : {sample_hash}")
    print(f"  Type          : {attr.get('type_description', 'N/A')}")
    print(f"  Size          : {attr.get('size', 'N/A')} bytes")
    for h in ("md5", "sha1", "sha256"):
        if attr.get(h):
            print(f"  {h.upper():<13} : {attr.get(h)}")
    names = attr.get("names") or []
    for nm in names:
        print(f"  Name          : {nm}")

    print("\n  ==== Artifact Import Table Information ====")
    import_list = pe.get("import_list") or []
    if import_list:
        for imp in import_list:
            dll = imp.get("library_name")
            funcs = imp.get("imported_functions") or []
            print(f"  [-] Imported Library : {dll}")
            for fn in funcs:
                print(f"        - {fn}")
    else:
        print("  [!] No Import Table information. Is this a binary artifact?")

    print("\n  ==== Artifact Section Information ====")
    sections = pe.get("sections") or []
    if sections:
        for sec in sections:
            name = sec.get("name")
            entropy = sec.get("entropy")
            flags = sec.get("flags")
            md5 = sec.get("md5")
            print(f"  [-] Section    : {name}")
            if isinstance(entropy, (int, float)) and entropy >= ENTROPY_THRESHOLD:
                print(f"      [!] Entropy : {entropy} (>= {ENTROPY_THRESHOLD}, "
                      "possibly packed/encrypted)")
            else:
                print(f"      [+] Entropy : {entropy}")
            if flags == "rx":
                print(f"      [!] Flags   : {flags} (writable+executable pattern)")
            else:
                print(f"      [+] Flags   : {flags}")
            print(f"      [-] MD5     : {md5}")
    else:
        print("  [!] No Section information. Is this a binary artifact?")


    print("\n  ==== Artifact Verdict Information ====")
    print(f"  [!] Malicious  : {stats.get('malicious', 0)}")
    print(f"  [!] Suspicious : {stats.get('suspicious', 0)}")
    print(f"  [+] Harmless   : {stats.get('harmless', 0)}")
    print(f"  [-] Undetected : {stats.get('undetected', 0)}")

    if vendor_name:
        print(f"\n  ==== Specific Vendor Analysis: {vendor_name} ====")
        results = attr.get("last_analysis_results", {}) or {}
        if vendor_name in results:
            v = results[vendor_name]
            cat = v.get("category", "N/A")
            res = v.get("result", "N/A")
            marker = "[!]" if cat in ("malicious", "suspicious") else "[+]"
            print(f"  {marker} Category  : {cat}")
            print(f"  {marker} Detection : {res}")
        else:
            print(f"  [!] Vendor '{vendor_name}' not found in the analysis list.")

    print("\n  ==== Artifact Classification Information ====")
    classification = "N/A"
    threat_type = "N/A"
    threat_tag = "N/A"
    ptc = attr.get("popular_threat_classification", {}) or {}
    names_list = ptc.get("popular_threat_name") or []
    if len(names_list) >= 1:
        classification = names_list[0].get("value", "N/A")
    if len(names_list) >= 2:
        threat_type = names_list[1].get("value", "N/A")
    threat_tag = ptc.get("suggested_threat_label", "N/A")
    print(f"  [!] VT Classification : {classification}")
    print(f"  [!] Threat Type       : {threat_type}")
    print(f"  [!] Threat Tag        : {threat_tag}")
    print(f"  [!] Imphash           : {pe.get('imphash', 'N/A')}")

    print("\n  ==== Public Intelligence - YARA Rules ====")
    yara_matches = attr.get("crowdsourced_yara_results") or []
    if yara_matches:
        for y in yara_matches:
            print(f"  [!] Rule    : {y.get('rule_name')}")
            print(f"      Author  : {y.get('author')}")
            print(f"      Source  : {y.get('source')}")
    else:
        print("  [!] No public YARA recurrences for this artifact.")

    print("\n  ==== Public Intelligence - Sigma Rules ====")
    sigma_matches = attr.get("sigma_analysis_results") or []
    if sigma_matches:
        for sig in sigma_matches:
            print(f"  [!] Rule        : {sig.get('rule_title')}")
            print(f"      Description : {sig.get('rule_description')}")
            print(f"      Source      : {sig.get('rule_source')}")
            print(f"      Author      : {sig.get('rule_author')}")
            for ctx in (sig.get("match_context") or []):
                values = ctx.get("values") or {}
                if values:
                    print("      Match Conditions:")
                    for k, v in values.items():
                        print(f"         {k}: {v}")
    else:
        print("  [!] No public Sigma recurrences for this artifact.")
    hr()

def extract_iocs(items, source):
    out = []
    for it in items:
        if source == "threatfox":
            if it.get("ioc"):
                out.append(it["ioc"])
            for sm in (it.get("malware_samples") or []):
                if sm.get("sha256_hash"):
                    out.append(sm["sha256_hash"])
        else:
            if it.get("sha256_hash"):
                out.append(it["sha256_hash"])
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq

def emit(raw_resp, items, source, args, pretty_fn):
    if getattr(args, "iocs_only", False):
        for ioc in extract_iocs(items, source):
            print(ioc)
    elif args.json:
        print(json.dumps(raw_resp, indent=2, ensure_ascii=False))
    else:
        pretty_fn(items)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(raw_resp, fh, indent=2, ensure_ascii=False)
        info(f"Response saved in: {args.output}")

def cmd_tf_ioc(args):
    key = resolve_auth_key(args.auth_key, "threatfox")
    payload = {"query": "search_ioc", "search_term": args.term,
               "exact_match": args.exact}
    resp = call_threatfox(payload, key)
    items = get_data(resp)
    emit(resp, items, "threatfox", args, print_threatfox_iocs)


def cmd_tf_hash(args):
    key = resolve_auth_key(args.auth_key, "threatfox")
    payload = {"query": "search_hash", "hash": args.hash}
    resp = call_threatfox(payload, key)
    items = get_data(resp)
    emit(resp, items, "threatfox", args, print_threatfox_iocs)


def cmd_tf_malware(args):
    key = resolve_auth_key(args.auth_key, "threatfox")
    payload = {"query": "malwareinfo", "malware": args.family,
               "limit": args.limit}
    resp = call_threatfox(payload, key)
    items = get_data(resp)
    emit(resp, items, "threatfox", args, print_threatfox_iocs)


def cmd_tf_tag(args):
    key = resolve_auth_key(args.auth_key, "threatfox")
    payload = {"query": "taginfo", "tag": args.tag, "limit": args.limit}
    resp = call_threatfox(payload, key)
    items = get_data(resp)
    emit(resp, items, "threatfox", args, print_threatfox_iocs)


def cmd_tf_recent(args):
    key = resolve_auth_key(args.auth_key, "threatfox")
    payload = {"query": "get_iocs", "days": args.days}
    resp = call_threatfox(payload, key)
    items = get_data(resp)
    emit(resp, items, "threatfox", args, print_threatfox_iocs)

def cmd_mb_hash(args):
    key = resolve_auth_key(args.auth_key, "malwarebazaar")
    data = {"query": "get_info", "hash": args.hash}
    resp = call_malwarebazaar(data, key)
    items = get_data(resp)
    if args.iocs_only:
        for ioc in extract_iocs(items, "malwarebazaar"):
            print(ioc)
    elif args.json:
        print(json.dumps(resp, indent=2, ensure_ascii=False))
    else:
        if not items:
            print("Hash desconhecido no MalwareBazaar.")
        for s in items:
            print_mb_full_info(s)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(resp, fh, indent=2, ensure_ascii=False)
        info(f"Response saved in: {args.output}")


def cmd_mb_tag(args):
    key = resolve_auth_key(args.auth_key, "malwarebazaar")
    data = {"query": "get_taginfo", "tag": args.tag, "limit": args.limit}
    resp = call_malwarebazaar(data, key)
    items = get_data(resp)
    emit(resp, items, "malwarebazaar", args, print_mb_samples)


def cmd_mb_sig(args):
    key = resolve_auth_key(args.auth_key, "malwarebazaar")
    data = {"query": "get_siginfo", "signature": args.signature,
            "limit": args.limit}
    resp = call_malwarebazaar(data, key)
    items = get_data(resp)
    emit(resp, items, "malwarebazaar", args, print_mb_samples)


def cmd_mb_imphash(args):
    key = resolve_auth_key(args.auth_key, "malwarebazaar")
    data = {"query": "get_imphash", "imphash": args.imphash,
            "limit": args.limit}
    resp = call_malwarebazaar(data, key)
    items = get_data(resp)
    emit(resp, items, "malwarebazaar", args, print_mb_samples)


def cmd_mb_yara(args):
    key = resolve_auth_key(args.auth_key, "malwarebazaar")
    data = {"query": "get_yarainfo", "yara_rule": args.rule,
            "limit": args.limit}
    resp = call_malwarebazaar(data, key)
    items = get_data(resp)
    emit(resp, items, "malwarebazaar", args, print_mb_samples)


def cmd_mb_recent(args):
    key = resolve_auth_key(args.auth_key, "malwarebazaar")
    data = {"query": "recent_detections", "hours": args.hours}
    resp = call_malwarebazaar(data, key)
    items = get_data(resp)
    emit(resp, items, "malwarebazaar", args, print_mb_samples)


def cmd_mb_download(args):
    key = resolve_auth_key(args.auth_key, "malwarebazaar")
    headers = {"Auth-Key": key}
    data = {"query": "get_file", "sha256_hash": args.sha256}
    info(f"Downloading the sample {args.sha256} ...")
    try:
        r = requests.post(MALWAREBAZAAR_API, data=data, headers=headers,
                          timeout=TIMEOUT)
    except requests.RequestException as e:
        sys.exit(f"[!] Failed on Network: {e}")
    ctype = r.headers.get("Content-Type", "")
    if "application/json" in ctype or r.content[:1] == b"{":
        try:
            status = r.json().get("query_status")
            sys.exit(f"[!] Download failed: query_status='{status}'")
        except ValueError:
            pass
    out = args.output or f"{args.sha256}.zip"
    with open(out, "wb") as fh:
        fh.write(r.content)
    print(f"[+] Sample saved in: {out}")
    print("    ZIP File protect wiht password: infected\n")


def cmd_vt_hash(args):
    key = resolve_vt_key(args.vt_api_key)
    resp = call_virustotal(f"files/{args.hash}", key)
    if args.iocs_only:
        if resp:
            print(args.hash)
    elif args.json:
        print(json.dumps(resp, indent=2, ensure_ascii=False))
    else:
        print_vt_hash(args.hash, resp, args.vendor)
    if args.output and resp is not None:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(resp, fh, indent=2, ensure_ascii=False)
        info(f"Response saved in: {args.output}")


def cmd_vt_ip(args):
    key = resolve_vt_key(args.vt_api_key)
    resp = call_virustotal(f"ip_addresses/{args.ip}", key)
    if args.iocs_only:
        if resp:
            print(args.ip)
    elif args.json:
        print(json.dumps(resp, indent=2, ensure_ascii=False))
    else:
        print_vt_ip(args.ip, resp)
    if args.output and resp is not None:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(resp, fh, indent=2, ensure_ascii=False)
        info(f"Response saved in: {args.output}")

def build_parser():
    parser = argparse.ArgumentParser(
        prog="threat_intell_hunting.py",
        description="Collect IOCs and samples via ThreatFox & MalwareBazaar "
                    "(abuse.ch) and triage artifacts/IPs via VirusTotal.",
        epilog="Free abuse.ch Auth-Key at https://auth.abuse.ch/ (--auth-key). "
               "VirusTotal API Key at https://www.virustotal.com/ (--vt-api-key).",
    )
    parser.add_argument("--version", action="version",
                       version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--auth-key", help="Auth-Key of abuse.ch.")
    common.add_argument("--json", action="store_true",
                       help="Output in raw JSON.")
    common.add_argument("--iocs-only", action="store_true",
                       help="Print just the indicadors, 1 per line.")
    common.add_argument("-o", "--output", metavar="FILE",
                       help="Save full JSON response on file.")

    vt_common = argparse.ArgumentParser(add_help=False)
    vt_common.add_argument("--vt-api-key", required=True,
                           help="VirusTotal API Key.")
    vt_common.add_argument("--json", action="store_true",
                           help="Output in raw JSON.")
    vt_common.add_argument("--iocs-only", action="store_true",
                           help="Print just the indicator, 1 per line.")
    vt_common.add_argument("-o", "--output", metavar="FILE",
                           help="Save full JSON response on file.")

    limit = argparse.ArgumentParser(add_help=False)
    limit.add_argument("--limit", type=int, default=100,
                      help="Max of results (default: 100, max: 1000).")

    p = sub.add_parser("tf-ioc", parents=[common],
                       help="ThreatFox: search for an IOC (IP, domain, URL).")
    p.add_argument("term", help="Ex.: 94.103.84.81")
    p.add_argument("--exact", action="store_true",
                   help="Exact match (default: wildcard).")
    p.set_defaults(func=cmd_tf_ioc)

    p = sub.add_parser("tf-hash", parents=[common],
                       help="ThreatFox: Associated IOCs on a Hash (MD5/SHA256).")
    p.add_argument("hash", help="MD5 or SHA256.")
    p.set_defaults(func=cmd_tf_hash)

    p = sub.add_parser("tf-malware", parents=[common, limit],
                       help="ThreatFox: IOCs malware family.")
    p.add_argument("family", help="Family (ex.: 'Cobalt Strike').")
    p.set_defaults(func=cmd_tf_malware)

    p = sub.add_parser("tf-tag", parents=[common, limit],
                       help="ThreatFox: IOCs for tag.")
    p.add_argument("tag", help="Tag (ex.: Magecart).")
    p.set_defaults(func=cmd_tf_tag)

    p = sub.add_parser("tf-recent", parents=[common],
                       help="ThreatFox: Recent IOCs")
    p.add_argument("--days", type=int, default=3,
                   help="Day windows like 1-7, the default is 3)")
    p.set_defaults(func=cmd_tf_recent)

    p = sub.add_parser("mb-hash", parents=[common],
                       help="MalwareBazaar: Sample details through a hash.")
    p.add_argument("hash", help="SHA256, SHA1 or MD5.")
    p.set_defaults(func=cmd_mb_hash)

    p = sub.add_parser("mb-tag", parents=[common, limit],
                       help="MalwareBazaar: samples by tag.")
    p.add_argument("tag", help="Tag (ex.: TrickBot).")
    p.set_defaults(func=cmd_mb_tag)

    p = sub.add_parser("mb-sig", parents=[common, limit],
                       help="MalwareBazaar: Sample by Signatures.")
    p.add_argument("signature", help="Signature (ex.: TrickBot).")
    p.set_defaults(func=cmd_mb_sig)

    p = sub.add_parser("mb-imphash", parents=[common, limit],
                       help="MalwareBazaar: Samples by Imphash.")
    p.add_argument("imphash", help="PE imphash.")
    p.set_defaults(func=cmd_mb_imphash)

    p = sub.add_parser("mb-yara", parents=[common, limit],
                       help="MalwareBazaar: Samples by Yara Rule")
    p.add_argument("rule", help="search by Rule Name (ex.: win_remcos_g0).")
    p.set_defaults(func=cmd_mb_yara)

    p = sub.add_parser("mb-recent", parents=[common],
                       help="MalwareBazaar: recent detections")
    p.add_argument("--hours", type=int, default=48,
                   help="Hour windows like 1-168, the default is 48")
    p.set_defaults(func=cmd_mb_recent)

    p = sub.add_parser("mb-download", parents=[common],
                       help="MalwareBazaar: Download the sample in a ZIP fil, with the password "
                            "'infected').")
    p.add_argument("sha256", help="SHA256 of the sample.")
    p.set_defaults(func=cmd_mb_download)

    p = sub.add_parser("vt-hash", parents=[vt_common],
                       help="VirusTotal: artifact triage by hash (imports, "
                            "sections, verdict, YARA/Sigma).")
    p.add_argument("hash", help="SHA256, SHA1 or MD5 of the sample.")
    p.add_argument("--vendor", dest="vendor", metavar="NAME",
                   help="Specific Security Vendor verdict "
                        "(ex.: 'SentinelOne (Static ML)').")
    p.set_defaults(func=cmd_vt_hash)

    p = sub.add_parser("vt-ip", parents=[vt_common],
                       help="VirusTotal: IP address reputation triage.")
    p.add_argument("ip", help="Ex.: 94.103.84.81")
    p.set_defaults(func=cmd_vt_ip)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    info(f"threat intell hunting v{VERSION} | {args.command} | {ts}")
    args.func(args)


if __name__ == "__main__":
    main()
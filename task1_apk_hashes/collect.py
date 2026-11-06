#!/usr/bin/env python3
"""
Задание 1: подборка хеш-сумм вредоносных APK с вердиктами вендоров.

Источники (только метаданные, образцы НЕ скачиваются):
  * MalwareBazaar (abuse.ch) — список свежих APK, семейство, теги, YARA,
    vendor_intel (ReversingLabs, Triage, ANY.RUN, Kaspersky/... и т.д.).
  * VirusTotal v3 — вердикты ~70 AV-движков, popular_threat_classification,
    androguard-метаданные, bundled_files (файлы внутри APK и их детекты) — бонус.

Ключи берутся из переменных окружения или из файла task1_apk_hashes/.keys:
    MB_AUTH_KEY=...
    VT_API_KEY=...

Все ответы кэшируются в cache/, поэтому скрипт можно перезапускать —
повторных запросов к API не будет (важно для лимита VT 4 req/min, 500/day).

Пример:
    python3 collect.py --mb-limit 1000 --vt-files 300 --vt-bundled 150
    python3 collect.py --report-only      # пересобрать отчёт из кэша
"""
import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
CACHE = HERE / "cache"
OUT = HERE / "out"

MB_URL = "https://mb-api.abuse.ch/api/v1/"
VT_URL = "https://www.virustotal.com/api/v3"
VT_DELAY = 15.5  # публичный API: 4 запроса в минуту

# Движки, которые выводим отдельными колонками в CSV (остальные — в JSON).
KEY_ENGINES = [
    "Kaspersky", "ESET-NOD32", "Avast-Mobile", "Avast", "AVG", "BitDefender",
    "BitDefenderFalx", "DrWeb", "Microsoft", "Symantec", "SymantecMobileInsight",
    "Fortinet", "Sophos", "TrendMicro", "Trustlook", "Ikarus", "K7GW",
    "McAfee", "Google", "Lionic", "Cynet", "Tencent", "Avira", "Yandex",
]


def load_keys():
    keys = {}
    f = HERE / ".keys"
    if f.exists():
        for line in f.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                keys[k.strip()] = v.strip().strip('"\'')
    for k in ("MB_AUTH_KEY", "VT_API_KEY"):
        if os.environ.get(k):
            keys[k] = os.environ[k]
    return keys


def http(url, data=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    req.add_header("User-Agent", "apk-hash-collector/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, {"raw": body[:500]}


def cached(name):
    p = CACHE / name
    return json.loads(p.read_text()) if p.exists() else None


def store(name, obj):
    p = CACHE / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=1))


# ---------------------------------------------------------------- MalwareBazaar
def mb_query(key, **params):
    data = urllib.parse.urlencode(params).encode()
    return http(MB_URL, data=data, headers={"Auth-Key": key})


ANDROID_FAMILIES = [
    "Hydra", "Cerberus", "Anubis", "SpyNote", "Joker", "FluBot", "Octo", "ERMAC",
    "Hook", "SharkBot", "Xenomorph", "TeaBot", "Alien", "BankBot", "IRATA",
    "SpinOk", "AhMyth", "Coper", "Brata", "GodFather", "Medusa", "Vultur",
    "Rafel", "CraxsRAT", "SpyMax", "Anatsa", "TgToxic", "Hydra", "BlackRock",
    "Chameleon", "Harly", "Triada", "Necro", "Mamont", "Rokrat", "AndroRAT",
    "DroidJack", "Dendroid", "Metasploit", "SOVA", "Nexus", "Albiriox",
    "Crocodilus", "SpyAgent", "Gigabud", "ToxicPanda", "BingoMod", "Ajina",
]
ANDROID_TAGS = ["apk", "android", "banker", "Android-Banker", "spyware"]


def mb_list_apk(key, limit):
    """Объединяет: последние APK + выборки по Android-семействам и тегам."""
    name = "mb/list_apk_all.json"
    c = cached(name)
    if c:
        return c
    seen = {}
    queries = [("get_file_type", {"file_type": "apk", "limit": 1000})]
    queries += [("get_siginfo", {"signature": s, "limit": 100}) for s in dict.fromkeys(ANDROID_FAMILIES)]
    queries += [("get_taginfo", {"tag": t, "limit": 300}) for t in ANDROID_TAGS]
    for q, p in queries:
        st, j = mb_query(key, query=q, **p)
        data = j.get("data") if st == 200 and j.get("query_status") == "ok" else []
        n = 0
        for row in data or []:
            if row.get("file_type") == "apk" and row["sha256_hash"] not in seen:
                seen[row["sha256_hash"]] = row
                n += 1
        print(f"  MB {q} {p}: +{n} (status {j.get('query_status')})", file=sys.stderr)
        time.sleep(0.5)
    rows = list(seen.values())[:limit]
    store(name, rows)
    return rows


def family_round_robin(rows):
    """Порядок обхода для VT: по одному образцу каждого семейства по кругу."""
    buckets = {}
    for r in rows:
        buckets.setdefault(r.get("signature") or "~unknown", []).append(r)
    order = sorted(buckets, key=lambda k: (k == "~unknown", k))
    out = []
    while any(buckets.values()):
        for k in order:
            if buckets[k]:
                out.append(buckets[k].pop(0))
    return out


def mb_info(key, sha256):
    name = f"mb/info/{sha256}.json"
    c = cached(name)
    if c is not None:
        return c
    st, j = mb_query(key, query="get_info", hash=sha256)
    d = j["data"][0] if st == 200 and j.get("query_status") == "ok" else {}
    store(name, d)
    time.sleep(0.3)
    return d


# ------------------------------------------------------------------ VirusTotal
_last_vt = [0.0]


def vt_get(key, path):
    wait = VT_DELAY - (time.time() - _last_vt[0])
    if wait > 0:
        time.sleep(wait)
    for attempt in range(3):
        _last_vt[0] = time.time()
        st, j = http(f"{VT_URL}{path}", headers={"x-apikey": key})
        if st == 429:  # квота
            code = j.get("error", {}).get("code", "")
            if code == "QuotaExceededError":
                return st, j
            time.sleep(60)
            continue
        return st, j
    return st, j


def vt_file(key, sha256, budget):
    name = f"vt/file/{sha256}.json"
    c = cached(name)
    if c is not None:
        return c
    if budget["files"] <= 0:
        return None
    st, j = vt_get(key, f"/files/{sha256}")
    if st == 429:
        budget["files"] = budget["bundled"] = 0
        print("  VT quota exceeded — дальше только кэш", file=sys.stderr)
        return None
    budget["files"] -= 1
    d = j.get("data", {}).get("attributes", {}) if st == 200 else {"_status": st}
    store(name, d)
    return d


def vt_bundled(key, sha256, budget):
    name = f"vt/bundled/{sha256}.json"
    c = cached(name)
    if c is not None:
        return c
    if budget["bundled"] <= 0:
        return None
    st, j = vt_get(key, f"/files/{sha256}/bundled_files?limit=40")
    if st == 429:
        budget["files"] = budget["bundled"] = 0
        return None
    budget["bundled"] -= 1
    items = []
    if st == 200:
        for it in j.get("data", []):
            a = it.get("attributes", {})
            items.append({
                "sha256": it.get("id"),
                "names": a.get("names", [])[:5],
                "type": a.get("type_description"),
                "size": a.get("size"),
                "stats": a.get("last_analysis_stats", {}),
                "results": {e: r.get("result") for e, r in
                            a.get("last_analysis_results", {}).items()
                            if r.get("category") == "malicious"},
            })
    else:
        items = {"_status": st, "_error": j.get("error")}
    store(name, items)
    return items


# --------------------------------------------------------------------- report
def summarize(mb_row, info, vt, bundled):
    r = {
        "sha256": mb_row["sha256_hash"],
        "sha1": mb_row.get("sha1_hash"),
        "md5": mb_row.get("md5_hash"),
        "first_seen": mb_row.get("first_seen"),
        "file_name": mb_row.get("file_name"),
        "mb_signature": mb_row.get("signature") or "",
        "mb_tags": ",".join(mb_row.get("tags") or []),
    }
    vi = (info or {}).get("vendor_intel") or {}
    rl = vi.get("ReversingLabs") or {}
    r["rl_threat_name"] = rl.get("threat_name") or ""
    r["rl_status"] = rl.get("status", "")
    r["rl_scanners"] = f"{rl['scanner_match']}/{rl['scanner_count']}" if rl.get("scanner_count") else ""
    r["kaspersky_opentip"] = (vi.get("Kaspersky") or {}).get("verdict") or ""
    r["filescan"] = (vi.get("FileScan-IO") or {}).get("verdict") or ""
    r["inquest"] = (vi.get("InQuest") or {}).get("verdict") or ""
    r["yoroi"] = (vi.get("YOROI_YOMI") or {}).get("detection") or ""
    sh = vi.get("Spamhaus_HBL")
    r["spamhaus"] = sh[0].get("detection", "") if isinstance(sh, list) and sh else ""
    triage = vi.get("Triage") or {}
    r["triage"] = f"{triage.get('malware_family') or ''} score={triage.get('score','')}".strip() if triage else ""
    anyrun = vi.get("ANY.RUN")
    if isinstance(anyrun, list) and anyrun:
        r["anyrun"] = anyrun[0].get("verdict", "")
    r["mb_yara"] = ";".join(y.get("rule_name", "") for y in (info or {}).get("yara_rules") or [])
    r["mb_vendors"] = {k: v for k, v in vi.items()}

    if vt and "_status" not in vt:
        st = vt.get("last_analysis_stats", {})
        r["vt_malicious"] = st.get("malicious", 0)
        r["vt_total"] = sum(st.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless"))
        ptc = vt.get("popular_threat_classification") or {}
        r["vt_label"] = ptc.get("suggested_threat_label", "")
        res = vt.get("last_analysis_results", {})
        r["vt_results"] = {e: x.get("result") for e, x in res.items() if x.get("category") == "malicious"}
        ag = vt.get("androguard") or {}
        r["package"] = ag.get("Package", "")
        r["main_activity"] = ag.get("main_activity", "")
        r["app_name"] = ag.get("AndroidApplicationInfo", {}).get("label", "") if isinstance(ag.get("AndroidApplicationInfo"), dict) else ""
        perms = ag.get("permission_details") or {}
        r["dangerous_perms"] = ",".join(sorted(p.split(".")[-1] for p, d in perms.items()
                                               if isinstance(d, dict) and d.get("permission_type") == "dangerous"))
    if isinstance(bundled, list):
        bad = [b for b in bundled if b["stats"].get("malicious", 0) > 0]
        bad.sort(key=lambda b: -b["stats"].get("malicious", 0))
        r["malicious_inner_files"] = [
            {"name": (b["names"] or ["?"])[0], "sha256": b["sha256"], "type": b["type"],
             "detections": b["stats"].get("malicious", 0),
             "sample_verdicts": dict(list(b["results"].items())[:5])}
            for b in bad]
    return r


def write_outputs(rows):
    OUT.mkdir(exist_ok=True)
    (OUT / "apk_verdicts.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1))

    # CSV 1: по одному образцу на строку, ключевые вендоры колонками
    cols = ["sha256", "md5", "sha1", "first_seen", "mb_signature", "vt_label",
            "vt_malicious", "vt_total", "package", "rl_threat_name", "rl_status", "rl_scanners",
            "kaspersky_opentip", "filescan", "inquest", "yoroi", "spamhaus", "triage",
            "mb_yara", "mb_tags"]
    nbase = len(cols)
    cols += KEY_ENGINES + ["malicious_inner_files"]
    with open(OUT / "apk_verdicts.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in rows:
            vr = r.get("vt_results", {})
            inner = "; ".join(f"{x['name']} ({x['detections']})" for x in r.get("malicious_inner_files", []))
            w.writerow([r.get(c, "") for c in cols[:nbase]] + [vr.get(e, "") for e in KEY_ENGINES] + [inner])

    # CSV 2: длинный формат sha256 / vendor / verdict — все вендоры
    with open(OUT / "apk_verdicts_long.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sha256", "source", "vendor", "verdict"])
        for r in rows:
            for e, v in sorted(r.get("vt_results", {}).items()):
                w.writerow([r["sha256"], "VirusTotal", e, v])
            for vendor, v in r.get("mb_vendors", {}).items():
                w.writerow([r["sha256"], "MalwareBazaar", vendor, json.dumps(v, ensure_ascii=False)[:300]])

    # CSV 3: бонус — вредоносные файлы внутри APK
    with open(OUT / "apk_inner_files.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["apk_sha256", "apk_family", "inner_file", "inner_sha256", "type", "vt_detections", "sample_verdicts"])
        for r in rows:
            for x in r.get("malicious_inner_files", []):
                w.writerow([r["sha256"], r.get("vt_label") or r["mb_signature"], x["name"], x["sha256"],
                            x["type"], x["detections"], json.dumps(x["sample_verdicts"], ensure_ascii=False)])

    # Markdown-отчёт
    with_vt = [r for r in rows if "vt_malicious" in r]
    fam = Counter(r["mb_signature"] or "n/a" for r in rows)
    inner_names = Counter()
    for r in rows:
        for x in r.get("malicious_inner_files", []):
            n = x["name"]
            inner_names["lib/*.so" if n.startswith("lib/") else
                         "assets/*" if n.startswith("assets/") else n] += 1
    L = ["# Подборка вредоносных APK с вердиктами вендоров", "",
         f"Всего образцов: **{len(rows)}**, с отчётом VirusTotal: **{len(with_vt)}**, "
         f"с разбором вложенных файлов: **{sum(1 for r in rows if 'malicious_inner_files' in r)}**.", "",
         "Источники: MalwareBazaar (abuse.ch) API, VirusTotal API v3. Образцы не скачивались.", "",
         "Файлы: `apk_verdicts.csv` (образец на строку), `apk_verdicts_long.csv` (все вендоры), "
         "`apk_inner_files.csv` (вредоносные файлы внутри APK), `apk_verdicts.json` (всё).", "",
         "## Семейства (по MalwareBazaar)", "", "| Семейство | Кол-во |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in fam.most_common(40)]
    vend = Counter(v for r in rows for v in r.get("mb_vendors", {}))
    L += ["", "## Покрытие вердиктами", "", "| Источник | Образцов |", "|---|---|",
          f"| VirusTotal (~70 AV) | {len(with_vt)} |"]
    L += [f"| {k} (через MalwareBazaar) | {v} |" for k, v in vend.most_common()]
    L += [f"| YARA (MalwareBazaar) | {sum(1 for r in rows if r.get('mb_yara'))} |"]
    L += ["", "## Пример: вердикты MalwareBazaar-вендоров (по 2 образца на семейство)", "",
          "| SHA-256 | Семейство | ReversingLabs | RL сканеры | Kaspersky | FileScan | Triage |",
          "|---|---|---|---|---|---|---|"]
    per = Counter()
    for r in rows:
        f = r["mb_signature"] or "n/a"
        if f == "n/a" or per[f] >= 2 or not r.get("rl_status"):
            continue
        per[f] += 1
        L.append(f"| `{r['sha256']}` | {f} | {r['rl_threat_name'] or r['rl_status']} | {r['rl_scanners']} | "
                 f"{r['kaspersky_opentip']} | {r['filescan']} | {r['triage']} |")
    if inner_names:
        L += ["", "## Где внутри APK лежит детектируемый код", "", "| Файл | Кол-во APK |", "|---|---|"]
        L += [f"| `{k}` | {v} |" for k, v in inner_names.most_common(20)]
    L += ["", "## Образцы (первые 100 с отчётом VT)", "",
          "| SHA-256 | Семейство | VT | Kaspersky | ESET-NOD32 | Avast-Mobile | DrWeb | Вредоносные файлы внутри |",
          "|---|---|---|---|---|---|---|---|"]
    for r in sorted(with_vt, key=lambda r: -r["vt_malicious"])[:100]:
        vr = r.get("vt_results", {})
        inner = "<br>".join(f"`{x['name']}` ({x['detections']})" for x in r.get("malicious_inner_files", [])[:3])
        L.append(f"| `{r['sha256']}` | {r['mb_signature'] or r.get('vt_label','')} | "
                 f"{r['vt_malicious']}/{r['vt_total']} | {vr.get('Kaspersky','')} | {vr.get('ESET-NOD32','')} | "
                 f"{vr.get('Avast-Mobile','')} | {vr.get('DrWeb','')} | {inner} |")
    (OUT / "REPORT.md").write_text("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mb-limit", type=int, default=1000, help="сколько APK взять из MalwareBazaar (max 1000)")
    ap.add_argument("--mb-info", type=int, default=1000, help="для скольких запросить get_info (vendor_intel)")
    ap.add_argument("--vt-files", type=int, default=300, help="бюджет запросов VT /files/{id} за запуск")
    ap.add_argument("--vt-bundled", type=int, default=150, help="бюджет запросов VT bundled_files за запуск")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--vt-key-name", default="VT_API_KEY", help="имя ключа VT в .keys (для 2-го воркера)")
    ap.add_argument("--reverse", action="store_true", help="обходить список с конца (2-й воркер)")
    ap.add_argument("--no-write", action="store_true", help="только наполнять кэш, отчёт не писать")
    a = ap.parse_args()

    keys = load_keys()
    keys["VT_API_KEY"] = keys.get(a.vt_key_name)
    if not a.report_only and not keys.get("MB_AUTH_KEY"):
        sys.exit("Нет MB_AUTH_KEY (env или .keys)")
    budget = {"files": a.vt_files if keys.get("VT_API_KEY") else 0,
              "bundled": a.vt_bundled if keys.get("VT_API_KEY") else 0}
    if a.report_only:
        budget = {"files": 0, "bundled": 0}
        mb = cached("mb/list_apk_all.json") or []
    else:
        mb = mb_list_apk(keys["MB_AUTH_KEY"], a.mb_limit)
    mb = family_round_robin(mb)
    if a.reverse:
        mb = mb[::-1]
    print(f"MalwareBazaar: {len(mb)} APK", file=sys.stderr)

    rows = []
    for i, row in enumerate(mb):
        h = row["sha256_hash"]
        info = cached(f"mb/info/{h}.json")
        if info is None and not a.report_only and i < a.mb_info:
            info = mb_info(keys["MB_AUTH_KEY"], h)
        vt = vt_file(keys.get("VT_API_KEY"), h, budget)
        bundled = None
        if vt and vt.get("last_analysis_stats", {}).get("malicious", 0) > 0:
            bundled = vt_bundled(keys.get("VT_API_KEY"), h, budget)
        rows.append(summarize(row, info, vt, bundled))
        if i % 25 == 0:
            print(f"  {i}/{len(mb)} vt_left={budget}", file=sys.stderr, flush=True)
            if not a.no_write:
                write_outputs(rows)
    if not a.no_write:
        write_outputs(rows)
    print(f"Готово: {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()

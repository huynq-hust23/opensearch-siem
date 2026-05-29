#!/usr/bin/env python3
"""
Deploy Sigma rules lên OpenSearch Security Analytics (SA).

Flow:
  1. Đọc tất cả .yml rules từ RULES_DIR (recursive)
  2. pySigma convert → Lucene query (ECS Windows pipeline)
  3. Bypass SA Custom Rules API bug → index thẳng vào .opensearch-sap-custom-rules-config
  4. Tạo SA Detector với tất cả custom rules
  5. SA Alert action → Webhook → TheHive

Usage:
    python3 deploy_sa_rules.py
"""

import os
import sys
import uuid
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sigma.rule import SigmaRule, SigmaLevel
from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.exceptions import SigmaError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# 1. CONFIG
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR  = Path(__file__).resolve().parent
ENV_FILE  = BASE_DIR / ".env"

def _load_env(p: Path) -> dict:
    e = {}
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                e[k.strip()] = v.strip()
    return e

_env = _load_env(ENV_FILE)

OPENSEARCH  = _env.get("OPENSEARCH_URL", "https://localhost:9200").rstrip("/")
OS_USER     = _env.get("OPENSEARCH_USER", "admin")
OS_PASS     = _env.get("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "admin")
THEHIVE_URL = _env.get("THEHIVE_URL", "https://thehive.huynnphotography.id.vn")
THEHIVE_KEY = _env.get("THEHIVE_API_KEY", "M9tqpqXvYdbDKovkzwsss4nc4LvGcEYJ")

RULES_DIR        = Path(__file__).parent
SA_RULES_INDEX   = ".opensearch-sap-custom-rules-config"
CATEGORY         = "windows"
DETECTOR_NAME    = "SIEM-Custom-Detector"
WORKERS          = 5
MIN_LEVEL        = SigmaLevel.MEDIUM
NOW              = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

# Index mapping theo logsource
INDEX_MAP = {
    ("windows", "security"):    "siem-winlogbeat-*",
    ("windows", "system"):      "siem-winlogbeat-*",
    ("windows", "application"): "siem-winlogbeat-*",
    ("windows", "sysmon"):      "siem-winlogbeat-*",
    ("windows", "powershell"):  "siem-winlogbeat-*",
    ("windows", None):          "siem-winlogbeat-*",
    ("suricata", "eve"):        "siem-suricata-*",
    ("suricata", None):         "siem-suricata-*",
    ("linux", "auth"):          "siem-filebeat-*",
    ("linux", "syslog"):        "siem-filebeat-*",
    ("linux", None):            "siem-filebeat-*",
}
DEFAULT_INDEX = "siem-general-*"


# ─────────────────────────────────────────────────────────────────────────────
# 2. SESSION
# ─────────────────────────────────────────────────────────────────────────────
def make_session() -> requests.Session:
    s        = requests.Session()
    s.auth   = (OS_USER, OS_PASS)
    s.verify = False
    retry    = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter  = HTTPAdapter(max_retries=retry)
    s.mount("http://",  adapter)
    s.mount("https://", adapter)
    return s


# ─────────────────────────────────────────────────────────────────────────────
# 3. CUSTOM FIELD MAP: Sigma raw fields → Winlogbeat fields
# ─────────────────────────────────────────────────────────────────────────────
WINLOGBEAT_FIELD_MAP: dict[str, str] = {
    # Process / Image
    "Image":                    "winlog.event_data.Image",
    "ParentImage":              "winlog.event_data.ParentImage",
    "CommandLine":              "winlog.event_data.CommandLine",
    "Commandline":              "winlog.event_data.CommandLine",
    "ParentCommandLine":        "winlog.event_data.ParentCommandLine",
    "ParentProcessId":          "winlog.event_data.ParentProcessId",
    "ParentProcessGuid":        "winlog.event_data.ParentProcessGuid",
    "NewProcessName":           "winlog.event_data.NewProcessName",
    "NewProcessId":             "winlog.event_data.NewProcessId",
    "ProcessId":                "winlog.event_data.ProcessId",
    "ProcessGuid":              "winlog.event_data.ProcessGuid",
    "ProcessName":              "winlog.event_data.ProcessName",
    "OriginalFileName":         "winlog.event_data.OriginalFileName",
    "IntegrityLevel":           "winlog.event_data.IntegrityLevel",
    "CurrentDirectory":         "winlog.event_data.CurrentDirectory",
    # Logon / Auth
    "LogonType":                "winlog.event_data.LogonType",
    "LogonProcessName":         "winlog.event_data.LogonProcessName",
    "LogonGuid":                "winlog.event_data.LogonGuid",
    "LogonId":                  "winlog.event_data.LogonId",
    "AuthenticationPackageName":"winlog.event_data.AuthenticationPackageName",
    "LmPackageName":            "winlog.event_data.LmPackageName",
    "IpAddress":                "winlog.event_data.IpAddress",
    "IpPort":                   "winlog.event_data.IpPort",
    "WorkstationName":          "winlog.event_data.WorkstationName",
    "ElevatedToken":            "winlog.event_data.ElevatedToken",
    "TokenElevationType":       "winlog.event_data.TokenElevationType",
    "ImpersonationLevel":       "winlog.event_data.ImpersonationLevel",
    # User/Subject/Target
    "TargetUserName":           "winlog.event_data.TargetUserName",
    "TargetDomainName":         "winlog.event_data.TargetDomainName",
    "TargetLogonId":            "winlog.event_data.TargetLogonId",
    "TargetUserSid":            "winlog.event_data.TargetUserSid",
    "TargetOutboundUserName":   "winlog.event_data.TargetOutboundUserName",
    "TargetOutboundDomainName": "winlog.event_data.TargetOutboundDomainName",
    "SubjectUserName":          "winlog.event_data.SubjectUserName",
    "SubjectDomainName":        "winlog.event_data.SubjectDomainName",
    "SubjectLogonId":           "winlog.event_data.SubjectLogonId",
    "SubjectUserSid":           "winlog.event_data.SubjectUserSid",
    "User":                     "winlog.event_data.User",
    "UserName":                 "winlog.event_data.UserName",
    "SamAccountName":           "winlog.event_data.SamAccountName",
    # LSASS / Process Access (Sysmon Event 10)
    "TargetImage":              "winlog.event_data.TargetImage",
    "SourceImage":              "winlog.event_data.SourceImage",
    "GrantedAccess":            "winlog.event_data.GrantedAccess",
    "CallTrace":                "winlog.event_data.CallTrace",
    # File
    "TargetFilename":           "winlog.event_data.TargetFilename",
    "ImageLoaded":              "winlog.event_data.ImageLoaded",
    "Signed":                   "winlog.event_data.Signed",
    "Signature":                "winlog.event_data.SignatureStatus",
    "SignatureStatus":          "winlog.event_data.SignatureStatus",
    "Hashes":                   "winlog.event_data.Hashes",
    # Network (Sysmon Event 3)
    "DestinationIp":            "winlog.event_data.DestinationIp",
    "DestinationPort":          "winlog.event_data.DestinationPort",
    "DestinationHostname":      "winlog.event_data.DestinationHostname",
    "SourceIp":                 "winlog.event_data.SourceIp",
    "SourcePort":               "winlog.event_data.SourcePort",
    "SourceHostname":           "winlog.event_data.SourceHostname",
    "Protocol":                 "winlog.event_data.Protocol",
    "Initiated":                "winlog.event_data.Initiated",
    # Registry
    "TargetObject":             "winlog.event_data.TargetObject",
    "Details":                  "winlog.event_data.Details",
    "EventType":                "winlog.event_data.EventType",
    # Service
    "ServiceName":              "winlog.event_data.ServiceName",
    "ServiceFileName":          "winlog.event_data.ServiceFileName",
    "ServiceType":              "winlog.event_data.ServiceType",
    "ServiceStartType":         "winlog.event_data.ServiceStartType",
    "ImagePath":                "winlog.event_data.ImagePath",
    # PowerShell
    "ScriptBlockText":          "winlog.event_data.ScriptBlockText",
    "Payload":                  "winlog.event_data.Payload",
    "ContextInfo":              "winlog.event_data.ContextInfo",
    "HostApplication":          "winlog.event_data.HostApplication",
    # DNS
    "QueryName":                "winlog.event_data.QueryName",
    "QueryResults":             "winlog.event_data.QueryResults",
    "QueryStatus":              "winlog.event_data.QueryStatus",
    # Security event misc
    "Status":                   "winlog.event_data.Status",
    "FailureCode":              "winlog.event_data.FailureCode",
    "ErrorCode":                "winlog.event_data.ErrorCode",
    "PrivilegeList":            "winlog.event_data.PrivilegeList",
    "AccessMask":               "winlog.event_data.AccessMask",
    "AccessList":               "winlog.event_data.AccessList",
    "AuditPolicyChanges":       "winlog.event_data.AuditPolicyChanges",
    "TaskName":                 "winlog.event_data.TaskName",
    "RuleName":                 "winlog.event_data.RuleName",
    "PipeName":                 "winlog.event_data.PipeName",
    # EventID / Channel (top-level)
    "EventID":                  "winlog.event_id",
    "Channel":                  "winlog.channel",
    "ComputerName":             "winlog.computer_name",
    "Provider_Name":            "winlog.provider_name",
    "hostname":                 "host.name",
    "src_ip":                   "winlog.event_data.IpAddress",
    "dst_ip":                   "winlog.event_data.DestinationIp",
    "dst_port":                 "winlog.event_data.DestinationPort",
}


def build_winlogbeat_pipeline():
    """Pipeline chuyển raw Sigma field names → Winlogbeat field names."""
    return ProcessingPipeline(items=[
        ProcessingItem(
            transformation=FieldMappingTransformation(
                {k: [v] for k, v in WINLOGBEAT_FIELD_MAP.items()}
            )
        )
    ])


def _extract_fields(properties: dict, prefix: str, result: dict):
    for name, defn in properties.items():
        full  = f"{prefix}{name}" if prefix else name
        ftype = defn.get("type")
        if ftype == "text":
            result[full] = f"{full}" if "keyword" in defn.get("fields", {}) else full
        elif ftype in ("keyword", "ip", "integer", "long", "float", "boolean", "date"):
            result[full] = full
        elif ftype is None and "properties" in defn:
            _extract_fields(defn["properties"], f"{full}.", result)


def build_keyword_map(session: requests.Session) -> dict:
    keyword_map = {}
    try:
        r = session.get(f"{OPENSEARCH}/siem-*/_mapping", timeout=15)
        if not r.ok:
            print(f"  [WARN] Cannot get mapping: {r.status_code}")
            return keyword_map
        for _, idx_data in r.json().items():
            props = idx_data.get("mappings", {}).get("properties", {})
            _extract_fields(props, "", keyword_map)
        print(f"  Mapped {len(keyword_map)} fields from index")
    except Exception as e:
        print(f"  [WARN] Mapping error: {e}")
    return keyword_map


def build_keyword_pipeline(keyword_map: dict):
    field_mapping = {
        field: [kw_field]
        for field, kw_field in keyword_map.items()
        if kw_field != field
    }
    if not field_mapping:
        return None
    return ProcessingPipeline(items=[
        ProcessingItem(transformation=FieldMappingTransformation(field_mapping))
    ])


# ─────────────────────────────────────────────────────────────────────────────
# 4. PIPELINE / INDEX HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def get_pipeline(rule: SigmaRule, keyword_pipeline=None):
    """
    Dùng custom Winlogbeat pipeline thay cho ECS pipeline.
    ECS pipeline map sang process.executable, user.name... nhưng log thực tế
    của Winlogbeat 7.x vẫn lưu dưới winlog.event_data.* nên phải dùng
    bộ map thực tế của dự án.
    """
    pipeline = build_winlogbeat_pipeline()
    if keyword_pipeline:
        return pipeline + keyword_pipeline
    return pipeline


def get_index(rule: SigmaRule) -> str:
    product = rule.logsource.product or ""
    service = rule.logsource.service or ""
    return (
        INDEX_MAP.get((product, service))
        or INDEX_MAP.get((product, None))
        or DEFAULT_INDEX
    )


def make_backend(rule: SigmaRule, keyword_pipeline=None) -> OpensearchLuceneBackend:
    pipeline = get_pipeline(rule, keyword_pipeline)
    return (
        OpensearchLuceneBackend(processing_pipeline=pipeline)
        if pipeline else OpensearchLuceneBackend()
    )


# ─────────────────────────────────────────────────────────────────────────────
# 5. LOAD RULES
# ─────────────────────────────────────────────────────────────────────────────
def load_rules(path: Path) -> list[tuple[Path, SigmaRule]]:
    rule_files = sorted(path.rglob("*.yml"))
    # Bỏ qua chính file này và các file Python
    rule_files = [f for f in rule_files if f.suffix == ".yml"]

    if not rule_files:
        print("No .yml rule files found.")
        sys.exit(0)

    print(f"Found {len(rule_files)} rule files")
    sigma_rules = []

    for f in rule_files:
        try:
            rule = SigmaRule.from_yaml(f.read_text())
            sigma_rules.append((f, rule))
            lvl = rule.level.name if rule.level else "?"
            print(f"  [RULE]  {rule.title} ({lvl})")
        except Exception as e:
            print(f"  [SKIP]  {f.name}: {e}")

    print(f"\n  Loaded: {len(sigma_rules)} rules")
    return sigma_rules


# ─────────────────────────────────────────────────────────────────────────────
# 6. CONVERT SIGMA → LUCENE
# ─────────────────────────────────────────────────────────────────────────────
def convert_rules(sigma_rules: list, keyword_pipeline=None) -> list[dict]:
    converted = []
    for f, rule in sigma_rules:   # f = Path to yaml file
        if rule.level is not None and rule.level < MIN_LEVEL:
            print(f"  [SKIP]  {rule.title} (level too low: {rule.level.name})")
            continue
        try:
            queries = make_backend(rule, keyword_pipeline).convert(SigmaCollection([rule]))
            if not queries:
                print(f"  [WARN]  No query generated: {rule.title}")
                continue

            tags = [{"value": str(t)} for t in (rule.tags or [])]
            fps  = [{"value": str(f)} for f in (rule.falsepositives or [])]
            refs = [{"value": str(r)} for r in (rule.references or [])]

            # Đọc raw YAML để lưu vào SA doc (bắt buộc, SA cần trường 'rule')
            raw_yaml = Path(f).read_text() if isinstance(f, (str, Path)) else ""

            converted.append({
                "id":          str(rule.id) if rule.id else str(uuid.uuid4()),
                "title":       rule.title,
                "level":       rule.level.name if rule.level else "MEDIUM",
                "index":       get_index(rule),
                "query":       queries[0].replace(r"\\\\", ""),
                "tags":        tags,
                "falsepositives": fps,
                "references":  refs,
                "author":      rule.author or "",
                "description": rule.description or "",
                "status":      str(rule.status) if rule.status else "experimental",
                "raw_yaml":    raw_yaml,   # ← thêm raw YAML
            })
            print(f"  [OK]    {rule.title} → {get_index(rule)}")
            print(f"          Query: {queries[0][:80]}...")
        except SigmaError as e:
            print(f"  [FAIL]  {rule.title}: {e}")
    return converted


# ─────────────────────────────────────────────────────────────────────────────
# 7. DEPLOY TO SA CUSTOM RULES INDEX
# ─────────────────────────────────────────────────────────────────────────────
def check_existing_rule(session: requests.Session, title: str) -> str | None:
    try:
        r = session.post(
            f"{OPENSEARCH}/{SA_RULES_INDEX}/_search",
            json={"query": {"match_all": {}}, "size": 1000},
            timeout=10,
        )
        hits = r.json().get("hits", {}).get("hits", [])
        for h in hits:
            if h.get("_source", {}).get("rule", {}).get("title") == title:
                return h["_id"]
        return None
    except Exception:
        return None


def deploy_sa_rule(session: requests.Session, rule: dict) -> dict:
    doc = {
        "rule": {
            "category":          CATEGORY,
            "title":             rule["title"],
            "log_source":        "",
            "description":       rule["description"],
            "references":        rule["references"],
            "tags":              rule["tags"],
            "level":             rule["level"].lower(),
            "false_positives":   rule["falsepositives"],
            "author":            rule["author"],
            "status":            rule["status"],
            "last_update_time":  NOW,
            "queries":           [{"value": rule["query"]}],
            "query_field_names": [],
            "aggregationQueries": [],
            "rule":              rule.get("raw_yaml", ""),   # ← SA yêu cầu trường này
        }
    }

    existing_id = check_existing_rule(session, rule["title"])
    try:
        if existing_id:
            r      = session.put(f"{OPENSEARCH}/{SA_RULES_INDEX}/_doc/{existing_id}",
                                 json=doc, timeout=15)
            action = "Updated"
        else:
            r      = session.post(f"{OPENSEARCH}/{SA_RULES_INDEX}/_doc",
                                  json=doc, timeout=15)
            action = "Created"

        if r.status_code in (200, 201):
            rid = r.json().get("_id")
            print(f"  [{action}] {rule['title']} → ID: {rid}")
            return {"title": rule["title"], "id": rid, "ok": True}
        else:
            print(f"  [ERROR] {rule['title']} → {r.status_code}: {r.text[:150]}")
            return {"title": rule["title"], "id": None, "ok": False}
    except Exception as e:
        print(f"  [ERROR] {rule['title']} → {e}")
        return {"title": rule["title"], "id": None, "ok": False}


def deploy_all_rules(session: requests.Session, converted: list[dict]) -> list[dict]:
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(deploy_sa_rule, session, r): r for r in converted}
        for f in as_completed(futures):
            results.append(f.result())
    # Refresh index để SA UI thấy ngay
    session.post(f"{OPENSEARCH}/{SA_RULES_INDEX}/_refresh")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 8. CREATE SA DETECTOR
# ─────────────────────────────────────────────────────────────────────────────
def setup_thehive_webhook(session: requests.Session) -> str | None:
    """
    Tạo TheHive webhook dùng OpenSearch Notifications API
    (/_plugins/_notifications/configs — thay thế destinations API cũ từ 2.12+).
    Trả về notification config_id để dùng trong SA trigger action.
    """
    NOTIF_URL = f"{OPENSEARCH}/_plugins/_notifications/configs"

    # Kiểm tra đã tồn tại chưa
    try:
        r = session.get(NOTIF_URL, timeout=10)
        if r.ok:
            for cfg in r.json().get("config_list", []):
                if cfg.get("config", {}).get("name") == "TheHive-Webhook":
                    cid = cfg["config_id"]
                    print(f"  TheHive webhook đã tồn tại: {cid}")
                    return cid
    except Exception:
        pass

    if not THEHIVE_KEY:
        print("  [WARN] THEHIVE_API_KEY chưa set trong .env — bỏ qua webhook")
        return None

    payload = {
        "config": {
            "name":        "TheHive-Webhook",
            "description": "Gửi alert từ OpenSearch SA sang TheHive",
            "config_type": "webhook",
            "is_enabled":  True,
            "webhook": {
                "url":    f"{THEHIVE_URL}/api/alert",
                "method": "POST",
                "header_params": {
                    "Authorization": f"Bearer {THEHIVE_KEY}",
                    "Content-Type":  "application/json",
                },
            }
        }
    }

    try:
        r = session.post(NOTIF_URL, json=payload, timeout=10)
        if r.ok:
            cid = r.json().get("config_id")
            print(f"  ✅ TheHive webhook created: {cid}")
            return cid
        else:
            print(f"  [WARN] Cannot create webhook: {r.status_code} {r.text[:150]}")
            return None
    except Exception as e:
        print(f"  [WARN] Webhook error: {e}")
        return None


def get_existing_detector(session: requests.Session) -> str | None:
    try:
        r = session.post(
            f"{OPENSEARCH}/_plugins/_security_analytics/detectors/_search",
            json={"query": {"match_all": {}}, "size": 100},
            timeout=10,
        )
        hits = r.json().get("hits", {}).get("hits", [])
        for h in hits:
            if h.get("_source", {}).get("name") == DETECTOR_NAME:
                return h["_id"]
        return None
    except Exception:
        return None


def create_detector(session: requests.Session, rule_ids: list[str], webhook_id: str | None):
    print(f"\n  Creating detector with {len(rule_ids)} custom rules...")

    # Build trigger actions
    actions = []
    if webhook_id:
        actions = [{
            "name":           "Send to TheHive",
            "destination_id": webhook_id,
            "message_template": {
                "source": json.dumps({
                    "type":        "SIEM_Alert",
                    "source":      "OpenSearch-SA",
                    "sourceRef":   "SA-{{ctx.detector.name}}-{{ctx.periodStart}}",
                    "title":       "{{ctx.detector.name}} triggered",
                    "description": "Security Analytics rule matched. Severity: {{ctx.trigger.severity}}",
                    "severity":    3,
                    "tlp":         2,
                })
            }
        }]

    payload = {
        "type":          "detector",
        "detector_type": CATEGORY,
        "name":          DETECTOR_NAME,
        "enabled":       True,
        "schedule": {
            "period": {"interval": 1, "unit": "MINUTES"}
        },
        "inputs": [{
            "detector_input": {
                "description":       "SIEM custom Sigma rules detector",
                "indices":           ["siem-winlogbeat-*"],
                "custom_rules":      [{"id": rid} for rid in rule_ids],
                "pre_packaged_rules": [],
                "time_field":        "@timestamp"
            }
        }],
        "triggers": [{
            "id":       "trigger-main",
            "name":     "Threat-Detected",
            "severity": "1",
            "types":    [],
            "ids":      [],
            "sev_levels": ["critical", "high", "medium", "low"],
            "tags":     [],
            "actions":  actions,
        }],
    }

    existing_id = get_existing_detector(session)
    try:
        if existing_id:
            r      = session.put(
                f"{OPENSEARCH}/_plugins/_security_analytics/detectors/{existing_id}",
                json=payload, timeout=30
            )
            action = "Updated"
        else:
            r      = session.post(
                f"{OPENSEARCH}/_plugins/_security_analytics/detectors",
                json=payload, timeout=30
            )
            action = "Created"

        if r.status_code in (200, 201):
            did = r.json().get("_id")
            print(f"  ✅ Detector {action}! ID: {did}")
            return did
        else:
            print(f"  ❌ Detector failed: {r.status_code}: {r.text[:200]}")
            return None
    except Exception as e:
        print(f"  ❌ Detector error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 9. MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    session = make_session()

    print("=" * 65)
    print("  OpenSearch SA — Sigma Rule Deployer")
    print(f"  Host      : {OPENSEARCH}")
    print(f"  Rules dir : {RULES_DIR}")
    print(f"  TheHive   : {THEHIVE_URL}")
    print("=" * 65)

    # ── Load rules ──
    print("\n=== Loading Sigma rules ===")
    sigma_rules = load_rules(RULES_DIR)

    # ── Build field map ──
    print("\n=== Building field map from OpenSearch ===")
    keyword_map      = build_keyword_map(session)
    keyword_pipeline = build_keyword_pipeline(keyword_map)

    # ── Convert ──
    print("\n=== Converting Sigma → Lucene ===")
    converted = convert_rules(sigma_rules, keyword_pipeline)

    if not converted:
        print("❌ No rules converted. Exiting.")
        sys.exit(1)

    # ── Deploy rules lên SA ──
    print(f"\n=== Deploying {len(converted)} rules to SA ===")
    results = deploy_all_rules(session, converted)

    ok  = [r for r in results if r["ok"]]
    err = [r for r in results if not r["ok"]]

    print(f"\n  ✅ Success : {len(ok)}/{len(results)}")
    print(f"  ❌ Failed  : {len(err)}/{len(results)}")

    if not ok:
        print("❌ No rules deployed successfully. Exiting.")
        sys.exit(1)

    # ── Setup TheHive webhook ──
    print("\n=== Setting up TheHive webhook ===")
    webhook_id = setup_thehive_webhook(session)

    # ── Tạo Detector ──
    print("\n=== Creating SA Detector ===")
    rule_ids = [r["id"] for r in ok if r["id"]]
    create_detector(session, rule_ids, webhook_id)

    # ── Summary ──
    print("\n" + "=" * 65)
    print("  SUMMARY")
    print("-" * 65)
    for r in results:
        icon = "✅" if r["ok"] else "❌"
        print(f"  {icon}  {r['title']}")
        if r["id"]:
            print(f"       ID: {r['id']}")
    print("=" * 65)
    print("\n💡 Vào SA → Detectors để xem detector vừa tạo!")
    print("💡 Vào SA → Rules → Custom Rules để xem rules!")


if __name__ == "__main__":
    main()
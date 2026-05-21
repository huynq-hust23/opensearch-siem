#!/usr/bin/env python3

import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from sigma.rule import SigmaRule, SigmaLevel
from sigma.correlations import SigmaCorrelationRule
from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.exceptions import SigmaError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── config ────────────────────────────────────────────────────────────────────
OPENSEARCH     = os.getenv("OPENSEARCH_URL",  "https://localhost:9200")
CREDS          = (os.getenv("OPENSEARCH_USER", "admin"),
                  os.getenv("OPENSEARCH_PASS", "123456"))
RULES_DIR      = Path(os.getenv("RULES_DIR",  "configs/sigma_rules"))
WORKERS        = int(os.getenv("WORKERS",     "10"))

MIN_LEVEL      = SigmaLevel.HIGH
SCHEDULE_MIN   = 1   # Cửa sổ mặc định cho các rule thông thường (phút)
CHANNEL_ID     = os.getenv("THEHIVE_CHANNEL_ID", "")

INDEX_MAP = {
    ("windows", "security"):    "siem-winlogbeat-*",
    ("windows", "system"):      "siem-winlogbeat-*",
    ("windows", "application"): "siem-winlogbeat-*",
    ("windows", "sysmon"):      "siem-winlogbeat-*",
    ("windows", None):          "siem-winlogbeat-*",
    ("suricata", "eve"):        "siem-suricata-*",
    ("suricata", None):         "siem-suricata-*",
    ("linux", "auth"):          "siem-filebeat-*",
    ("linux", "syslog"):        "siem-filebeat-*",
    ("linux", None):            "siem-filebeat-*",
}

DEFAULT_INDEX = "siem-general-*"

# ─────────────────────────────────────────────────────────────────────────────


# ── session ───────────────────────────────────────────────────────────────────
def make_session() -> requests.Session:
    session        = requests.Session()
    session.auth   = CREDS
    session.verify = False  # Đổi thành True nếu chạy trên Production có CA Certificate
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    return session
# ─────────────────────────────────────────────────────────────────────────────


# ── mapping helpers ───────────────────────────────────────────────────────────
def _extract_fields(properties: dict, prefix: str, result: dict):
    for name, defn in properties.items():
        full  = f"{prefix}{name}" if prefix else name
        ftype = defn.get("type")
        if ftype == "text":
            result[full] = f"{full}.keyword" if "keyword" in defn.get("fields", {}) else full
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
    except Exception as e:
        print(f"  [WARN] Mapping error: {e}")
    return keyword_map


def get_keyword_field(field: str, keyword_map: dict) -> str:
    if field in keyword_map:
        return keyword_map[field]
    ecs_safe = ("source.ip", "destination.ip", "client.ip", "server.ip")
    if field in ecs_safe:
        return field
    return f"{field}.keyword"


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


# ── pipeline / index helpers ──────────────────────────────────────────────────
def get_pipeline(rule: SigmaRule):
    # Nhận diện quy tắc Windows chuẩn và dịch tự động sang ECS (process.executable...)
    if rule.logsource.product == "windows":
        return ecs_windows()
    return None


def get_index(rule: SigmaRule) -> str:
    product = rule.logsource.product or ""
    service = rule.logsource.service or ""
    return (
        INDEX_MAP.get((product, service))
        or INDEX_MAP.get((product, None))
        or DEFAULT_INDEX
    )


def make_backend(rule: SigmaRule, keyword_pipeline=None) -> OpensearchLuceneBackend:
    pipeline = get_pipeline(rule)
    if keyword_pipeline:
        pipeline = (pipeline + keyword_pipeline) if pipeline else keyword_pipeline
    return OpensearchLuceneBackend(processing_pipeline=pipeline) \
           if pipeline else OpensearchLuceneBackend()
# ─────────────────────────────────────────────────────────────────────────────


# ── load ──────────────────────────────────────────────────────────────────────
def load_rules(path: Path):
    rule_files = sorted(path.rglob("*.yml"))
    if not rule_files:
        print("No rules found.")
        sys.exit(0)
    print(f"Found {len(rule_files)} rule files")

    sigma_rules: list[tuple[Path, SigmaRule]]            = []
    corr_rules:  list[tuple[Path, SigmaCorrelationRule]] = []

    for f in rule_files:
        for doc in [d.strip() for d in f.read_text().split("\n---\n") if d.strip()]:
            try:
                corr = SigmaCorrelationRule.from_yaml(doc)
                corr_rules.append((f, corr))
                print(f"  [CORR]  {corr.title}")
            except Exception:
                try:
                    rule = SigmaRule.from_yaml(doc)
                    sigma_rules.append((f, rule))
                    lvl = rule.level.name if rule.level else "?"
                    print(f"  [RULE]  {rule.title} ({lvl})")
                except Exception as e:
                    print(f"  [ERROR] {f.name}: {e}")

    print(f"\n  Normal: {len(sigma_rules)}, Correlation: {len(corr_rules)}")
    return sigma_rules, corr_rules
# ─────────────────────────────────────────────────────────────────────────────


# ── convert ───────────────────────────────────────────────────────────────────
def convert_normal(sigma_rules: list, keyword_pipeline=None) -> list[dict]:
    converted = []
    for _, rule in sigma_rules:
        if rule.level is not None and rule.level < MIN_LEVEL:
            print(f"  [SKIP]  {rule.title} (level too low)")
            continue
        try:
            queries = make_backend(rule, keyword_pipeline).convert(SigmaCollection([rule]))
            if not queries:
                print(f"  [WARN]  No query: {rule.title}")
                continue
            converted.append({
                "id":    str(rule.id),
                "title": rule.title,
                "level": rule.level.name if rule.level else "UNKNOWN",
                "index": get_index(rule),
                "query": queries[0],
                "type":  "normal",
            })
            print(f"  [OK]    {rule.title} → {get_index(rule)}")
        except SigmaError as e:
            print(f"  [FAIL]  {rule.title}: {e}")
    return converted


def convert_correlation(sigma_rules: list, corr_rules: list, keyword_map: dict, keyword_pipeline=None) -> list[dict]:
    converted = []
    by_name   = {r.name: r for _, r in sigma_rules if hasattr(r, "name") and r.name}

    for _, corr in corr_rules:
        if corr.level is not None and corr.level < MIN_LEVEL:
            print(f"  [SKIP]  {corr.title} (level too low)")
            continue
        try:
            base_rules = []
            for rule_ref in corr.rules:
                ref       = rule_ref.reference if rule_ref else None
                base_rule = by_name.get(str(ref)) if ref else None
                if base_rule:
                    base_rules.append(base_rule)
                else:
                    print(f"  [WARN]  Base rule not found: '{ref}' — available: {list(by_name)}")

            if not base_rules:
                print(f"  [WARN]  No base rules resolved for: {corr.title}")
                continue

            group_by  = get_keyword_field(
                corr.group_by[0] if corr.group_by else "source.ip", keyword_map
            )
            timespan  = corr.timespan.spec if corr.timespan else "5m"
            threshold = corr.condition.count if corr.condition else 5

            for base_rule in base_rules:
                base_query = make_backend(base_rule, keyword_pipeline).convert(SigmaCollection([base_rule]))
                if not base_query:
                    print(f"  [WARN]  No base query for: {corr.title} / {base_rule.name}")
                    continue

                index = get_index(base_rule)
                monitor_title = f"{corr.title} [{base_rule.name}]" if len(base_rules) > 1 else corr.title

                converted.append({
                    "id":        f"{corr.id}_{base_rule.name}" if len(base_rules) > 1 else str(corr.id),
                    "title":     monitor_title,
                    "level":     corr.level.name if corr.level else "UNKNOWN",
                    "index":     index,
                    "threshold": threshold,
                    "timespan":  timespan,
                    "type":      "correlation",
                    "query": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "must":   [{"query_string": {"query": base_query[0]}}],
                                "filter": [{"range": {"@timestamp": {"gte": f"now-{timespan}"}}}],
                            }
                        },
                        "aggs": {"by_field": {"terms": {"field": group_by, "size": 100}}},
                    },
                })
                print(f"  [OK]    {monitor_title} (>= {threshold} per {timespan} by {group_by}) → {index}")

        except Exception as e:
            print(f"  [FAIL]  {corr.title}: {e}")

    return converted
# ─────────────────────────────────────────────────────────────────────────────


# ── deploy ────────────────────────────────────────────────────────────────────
def get_all_monitors(session: requests.Session) -> dict:
    try:
        r = session.post(
            f"{OPENSEARCH}/_plugins/_alerting/monitors/_search",
            json={"size": 10000, "query": {"match_all": {}}},
            timeout=15,
        )
        hits = r.json().get("hits", {}).get("hits", [])
        return {hit["_source"]["name"]: hit["_id"] for hit in hits}
    except Exception as e:
        print(f"  [WARN] Cannot fetch existing monitors: {e}")
        return {}


def _parse_timespan_minutes(spec: str) -> int:
    """Đã sửa: Đảm bảo nếu timespan là vài giây (ví dụ 30s) thì monitor vẫn được đặt lịch tối thiểu là 1 phút của OpenSearch"""
    import re
    m = re.match(r"(\d+)([smhd])", spec)
    if not m:
        return SCHEDULE_MIN
    val, unit = int(m.group(1)), m.group(2)
    if unit == "s":
        return 1  # OpenSearch định kỳ tối thiểu là 1 phút
    if unit == "m":
        return max(1, val)
    if unit == "h":
        return val * 60
    if unit == "d":
        return val * 1440
    return SCHEDULE_MIN

def build_monitor(rule: dict) -> dict:
    thehive_action = {
        "name": "Send to TheHive",
        "destination_id": CHANNEL_ID,  
        "message_template": {
            "source": """{
                "type": "SIEM_Alert",
                "source": "OpenSearch-Sigma",
                "sourceRef": "{{ctx.monitor.name}}-{{ctx.periodStart}}",
                "title": \"""" + rule["title"] + """\",
                "description": "Sigma Rule Detected on index: """ + rule["index"] + """.\\nMonitor ID: {{ctx.monitor.name}}\\nSeverity Level: """ + rule["level"] + """\\nTotal Hits: {{ctx.results.0.hits.total.value}}",
                "severity": 3,
                "tlp": 2,
                "pap": 2,
                "date": {{ctx.periodStart}}
            }""",
            "lang": "mustache"
        }
    }

    if rule["type"] == "correlation":
        schedule_min = _parse_timespan_minutes(rule.get("timespan", "5m"))
        dsl = rule["query"]

        return {
            "name":          rule["id"],
            "type":          "monitor",
            "monitor_type":  "bucket_level_monitor",
            "enabled":       True,
            "schedule":      {"period": {"interval": schedule_min, "unit": "MINUTES"}},
            "inputs": [{
                "search": {
                    "indices": [rule["index"]],
                    "query":   dsl,
                }
            }],
            "triggers": [{
                "bucket_level_trigger": {
                    "id":       "trigger-" + rule["id"],
                    "name":     rule["title"],
                    "severity": "1",
                    "condition": {
                        "buckets_path": {"_count": "_count"},
                        "parent_bucket_path": "by_field",
                        "script": {
                            "source": f"params._count >= {rule['threshold']}",
                            "lang":   "painless",
                        },
                    },
                    "actions": [thehive_action], # ← Đã sửa: Gắn action gửi TheHive vào đây
                }
            }],
        }
    else:
        schedule_min = SCHEDULE_MIN
        dsl = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": rule["query"]}}],
                    "filter": [{
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{SCHEDULE_MIN}m"
                            }
                        }
                    }]
                }
            }
        }

        return {
            "name":         rule["id"],
            "type":         "monitor",
            "monitor_type": "query_level_monitor",
            "enabled":      True,
            "schedule":     {"period": {"interval": schedule_min, "unit": "MINUTES"}},
            "inputs": [{"search": {"indices": [rule["index"]], "query": dsl}}],
            "triggers": [{
                "query_level_trigger": {
                    "id":        "trigger-" + rule["id"],
                    "name":      rule["title"],
                    "severity":  "1",
                    "condition": {
                        "script": {
                            "source": "ctx.results[0].hits.total.value > 0",
                            "lang":   "painless",
                        }
                    },
                    "actions": [thehive_action], # ← Đã sửa: Gắn action gửi TheHive vào đây
                }
            }],
        }


def deploy_one(rule: dict, session: requests.Session, existing: dict) -> str:
    monitor = build_monitor(rule)
    eid     = existing.get(rule["id"])
    try:
        if eid:
            r      = session.put(f"{OPENSEARCH}/_plugins/_alerting/monitors/{eid}",
                                 json=monitor, timeout=10)
            action = "Updated"
        else:
            r      = session.post(f"{OPENSEARCH}/_plugins/_alerting/monitors",
                                  json=monitor, timeout=10)
            action = "Created"

        if r.ok:
            return f"  [{action}] {rule['title']} ({rule['type']})"
        return f"  [ERROR] {rule['title']} — {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return f"  [ERROR] {rule['title']} — {e}"


def deploy(converted: list[dict], session: requests.Session):
    print(f"\nFetching existing monitors...")
    existing = get_all_monitors(session)
    print(f"  Found {len(existing)} existing monitors")

    print(f"\nDeploying {len(converted)} monitors (workers={WORKERS})...")
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(deploy_one, r, session, existing): r for r in converted}
        for f in as_completed(futures):
            print(f.result())
# ─────────────────────────────────────────────────────────────────────────────


def main():
    session = make_session()

    print("=== Loading rules ===")
    sigma_rules, corr_rules = load_rules(RULES_DIR)

    print("\n=== Building field map from OpenSearch ===")
    keyword_map = build_keyword_map(session)
    print(f"  Mapped {len(keyword_map)} fields")
    keyword_pipeline = build_keyword_pipeline(keyword_map)
    kw_count = sum(1 for v in keyword_map.values() if v.endswith(".keyword"))
    print(f"  Keyword pipeline: {kw_count} text→keyword field mappings")

    print("\n=== Converting normal rules ===")
    converted = convert_normal(sigma_rules, keyword_pipeline)

    print("\n=== Converting correlation rules ===")
    converted += convert_correlation(sigma_rules, corr_rules, keyword_map, keyword_pipeline)

    if not converted:
        print("Nothing to deploy.")
        return

    print(f"\n=== Deploying {len(converted)} rules ===")
    deploy(converted, session)
    print("\nDone.")


if __name__ == "__main__":
    main()
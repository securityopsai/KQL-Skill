#!/usr/bin/env python3
"""
Sentinel analytics-rule template lint.

Checks an ARM template (portal export, hand-built, or generated) of
Microsoft.SecurityInsights/alertRules resources against the limits the Sentinel API
enforces at create/update time, so an import failure is found on your laptop and not
in the deployment error body. Stdlib only.

    python sentinel_template_lint.py rules.json              # human-readable report
    python sentinel_template_lint.py rules.json --strict     # warnings fail too
    python sentinel_template_lint.py rules.json --json       # machine-readable

Accepts: a full ARM deployment template ({"resources": [...]}), a bare list of
alertRules resources, or a single resource object. Hunting queries
(Microsoft.OperationalInsights/workspaces/savedSearches) in a template are linted too. Sentinel-repo YAML (one rule per
file) is accepted when PyYAML is installed; the YAML field names are mapped onto the
ARM ones before checking.

Exit code 0 = no errors (warnings may remain), 1 = at least one error, 2 = unusable input.

The limits implemented here are documented in references/sentinel-platform-contract.md.
What this script cannot do is validate KQL against your workspace schema — a column or
table that does not exist there still fails the deployment. Run the query in Logs.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# ---- enums and limits (keep in sync with references/sentinel-platform-contract.md) ----

MAX_FORMAT_PLACEHOLDERS = 3
MAX_DISPLAY_FORMAT_CHARS = 256
MAX_DESCRIPTION_FORMAT_CHARS = 5000
MAX_CUSTOM_DETAILS = 20
MAX_CUSTOM_DETAIL_KEY_CHARS = 20
MAX_ENTITY_MAPPINGS = 10
MAX_FIELD_MAPPINGS_PER_ENTITY = 3
MAX_QUERY_CHARS = 10_000
MIN_SCHEDULE_SECONDS = 5 * 60
MAX_SCHEDULE_SECONDS = 14 * 24 * 3600
MAX_PERIOD_WHEN_FREQ_OVER_1H_SECONDS = 48 * 3600
MIN_GROUPING_LOOKBACK_SECONDS = 5 * 60
MAX_GROUPING_LOOKBACK_SECONDS = 7 * 24 * 3600

SEVERITIES = {"Informational", "Low", "Medium", "High"}
TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery",
    "LateralMovement", "Collection", "Exfiltration", "CommandAndControl", "Impact",
    "PreAttack", "ImpairProcessControl", "InhibitResponseFunction",
}
TECHNIQUE_RE = re.compile(r"^T\d{4}$")
SUBTECHNIQUE_RE = re.compile(r"^T\d{4}\.\d{3}$")
AGGREGATION_KINDS = {"SingleAlert", "AlertPerResult"}
# Members ARM accepts on a template resource (a portal export's "id" is not one: Sentinel's
# Import ignores it, "Deploy a custom template" / az deployment can reject it).
ARM_RESOURCE_MEMBERS = {"type", "apiVersion", "name", "kind", "etag", "properties", "dependsOn",
                        "location", "tags", "scope", "condition", "comments", "copy"}
ARM_ROOT_MEMBERS = {"$schema", "contentVersion", "apiProfile", "metadata", "parameters", "variables",
                    "functions", "resources", "outputs"}
# Documented ScheduledAlertRuleProperties (union over API versions, learn.microsoft.com/azure/templates)
SCHEDULED_PROPERTIES = {
    "alertDetailsOverride", "alertRuleTemplateName", "customDetails", "description", "displayName",
    "enabled", "entityMappings", "eventGroupingSettings", "incidentConfiguration", "query",
    "queryFrequency", "queryPeriod", "severity", "suppressionDuration", "suppressionEnabled", "tactics",
    "techniques", "subTechniques", "sentinelEntitiesMappings", "templateVersion", "triggerOperator",
    "triggerThreshold", "startTimeUtc",  # startTimeUtc: scheduled start, set by portal exports
}
# subTechniques / sentinelEntitiesMappings exist only in PREVIEW api versions from 2023-12-01-preview
# (2023-03-01-preview for sentinelEntitiesMappings). Every GA version (2024-03-01 ... 2025-09-01) lacks them.
PREVIEW_ONLY_PROPERTIES = {"subTechniques": "2023-12-01", "sentinelEntitiesMappings": "2023-03-01"}
SAVED_SEARCH_TYPE = "Microsoft.OperationalInsights/workspaces/savedSearches"
SAVED_SEARCH_PROPERTIES = {"category", "displayName", "query", "version", "tags", "functionAlias",
                           "functionParameters"}
MATCHING_METHODS = {"AllEntities", "AnyAlert", "Selected"}
GROUP_BY_ALERT_DETAILS = {"DisplayName", "Severity"}
DYNAMIC_PROPERTIES = {
    "AlertLink", "ConfidenceLevel", "ConfidenceScore", "ExtendedLinks",
    "ProductComponentName", "ProductName", "ProviderName", "RemediationSteps",
    "Techniques", "SubTechniques",
}
ENTITY_IDENTIFIERS = {
    "Account": {"Name", "FullName", "NTDomain", "DnsDomain", "UPNSuffix", "Sid", "AadUserId",
                "AadTenantId", "PUID", "ObjectGuid", "DisplayName", "IsDomainJoined",
                "CloudAppAccountId"},
    "Host": {"HostName", "FullName", "NTDomain", "DnsDomain", "NetBiosName", "AzureID",
             "OMSAgentID", "OSFamily", "OSVersion", "IsDomainJoined"},
    "IP": {"Address"},
    "URL": {"Url"},
    "DNS": {"DomainName"},
    "AzureResource": {"ResourceId"},
    "File": {"Directory", "Name"},
    "FileHash": {"Algorithm", "Value"},
    "Process": {"ProcessId", "CommandLine", "ElevationToken", "CreationTimeUtc"},
    "CloudApplication": {"AppId", "Name", "InstanceName"},
    "RegistryKey": {"Hive", "Key"},
    "RegistryValue": {"Name", "Value", "ValueType"},
    "SecurityGroup": {"DistinguishedName", "SID", "ObjectGuid"},
    "Malware": {"Name", "Category"},
    "Mailbox": {"MailboxPrimaryAddress", "DisplayName", "Upn", "ExternalDirectoryObjectId",
                "RiskLevel"},
    "MailCluster": {"NetworkMessageIds", "CountByDeliveryStatus", "CountByThreatType",
                    "CountByProtectionStatus", "Threats", "Query", "QueryTime",
                    "MailCount", "IsVolumeAnomaly", "Source", "ClusterSourceIdentifier",
                    "ClusterSourceType", "ClusterQueryStartTime", "ClusterQueryEndTime",
                    "ClusterGroup"},
    "MailMessage": {"Recipient", "Urls", "Threats", "Sender", "P1Sender", "P1SenderDisplayName",
                    "P1SenderDomain", "SenderIP", "P2Sender", "P2SenderDisplayName",
                    "P2SenderDomain", "ReceivedDate", "NetworkMessageId", "InternetMessageId",
                    "Subject", "BodyFingerprintBin1", "BodyFingerprintBin2",
                    "BodyFingerprintBin3", "BodyFingerprintBin4", "BodyFingerprintBin5",
                    "AntispamDirection", "DeliveryAction", "DeliveryLocation", "Language",
                    "ThreatDetectionMethods"},
    "SubmissionMail": {"NetworkMessageId", "Timestamp", "Recipient", "Sender", "SenderIp",
                       "Subject", "ReportType", "SubmissionId", "SubmissionDate", "Submitter"},
}
PLACEHOLDER_RE = re.compile(r"\{\{([^{}]*)\}\}")
GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
ISO_DURATION_RE = re.compile(
    r"^P(?:(?P<d>\d+)D)?(?:T(?:(?P<h>\d+)H)?(?:(?P<m>\d+)M)?(?:(?P<s>\d+)S)?)?$")


def iso_seconds(value):
    """ISO 8601 duration (PT1H, P7D, PT5H30M) -> seconds, or None when unparseable."""
    if not isinstance(value, str):
        return None
    m = ISO_DURATION_RE.match(value.strip())
    if not m or value.strip() in ("P", "PT"):
        return None
    d, h, mi, s = (int(m.group(k) or 0) for k in ("d", "h", "m", "s"))
    return d * 86400 + h * 3600 + mi * 60 + s


def human(seconds):
    if seconds is None:
        return "?"
    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}m"


# ---- input normalisation ---------------------------------------------------------------

YAML_TO_ARM = {
    "name": "displayName", "description": "description", "severity": "severity",
    "query": "query", "queryFrequency": "queryFrequency", "queryPeriod": "queryPeriod",
    "triggerOperator": "triggerOperator", "triggerThreshold": "triggerThreshold",
    "tactics": "tactics", "entityMappings": "entityMappings", "customDetails": "customDetails",
    "alertDetailsOverride": "alertDetailsOverride", "incidentConfiguration": "incidentConfiguration",
    "eventGroupingSettings": "eventGroupingSettings", "suppressionDuration": "suppressionDuration",
    "suppressionEnabled": "suppressionEnabled", "enabled": "enabled",
}


def kql_timespan_to_iso(value):
    """Rule-YAML uses KQL timespans (1h, 7d, 30m); ARM uses ISO 8601."""
    if not isinstance(value, str):
        return value
    m = re.match(r"^(\d+)([dhm])$", value.strip())
    if not m:
        return value
    n, unit = int(m.group(1)), m.group(2)
    return {"d": f"P{n}D", "h": f"PT{n}H", "m": f"PT{n}M"}[unit]


def yaml_rule_to_resource(doc):
    props = {}
    for src, dst in YAML_TO_ARM.items():
        if src in doc:
            props[dst] = doc[src]
    for k in ("queryFrequency", "queryPeriod", "suppressionDuration"):
        if k in props:
            props[k] = kql_timespan_to_iso(props[k])
    techniques, subs = [], []
    for t in doc.get("relevantTechniques", []) or []:
        (subs if "." in str(t) else techniques).append(str(t))
    for s in subs:  # parent must be present in techniques
        parent = s.split(".")[0]
        if parent not in techniques:
            techniques.append(parent)
    props["techniques"] = techniques
    props["subTechniques"] = subs
    props.setdefault("enabled", True)
    return {
        "name": doc.get("id", "<yaml-rule-without-id>"),
        "kind": doc.get("kind", "Scheduled"),
        "type": "Microsoft.SecurityInsights/alertRules",
        "apiVersion": "yaml",
        "properties": props,
        "_source": "yaml",
    }


def load_resources(path):
    text = Path(path).read_text(encoding="utf-8")
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError:
            sys.exit("PyYAML is not installed; convert the rule to ARM JSON or `pip install pyyaml`.")
        docs = [d for d in yaml.safe_load_all(text) if d]
        return [yaml_rule_to_resource(d) for d in docs]
    data = json.loads(text)
    if isinstance(data, dict) and "resources" in data:
        return [r for r in data["resources"]
                if str(r.get("type", "")).endswith("Microsoft.SecurityInsights/alertRules")
                or "/alertRules" in str(r.get("type", ""))
                or r.get("type") == SAVED_SEARCH_TYPE]
    if isinstance(data, dict) and "properties" in data:
        return [data]
    if isinstance(data, list):
        return data
    sys.exit("Unrecognised input: expected an ARM template, a resource list or one resource.")


# ---- checks ----------------------------------------------------------------------------

class Findings:
    def __init__(self, rule_label):
        self.rule = rule_label
        self.items = []  # (level, where, message)

    def error(self, where, msg):
        self.items.append(("ERROR", where, msg))

    def warn(self, where, msg):
        self.items.append(("WARN", where, msg))

    @property
    def errors(self):
        return [i for i in self.items if i[0] == "ERROR"]

    @property
    def warnings(self):
        return [i for i in self.items if i[0] == "WARN"]


def column_in_query(col, query):
    """Heuristic: the column name appears as a whole word in the query text.
    Table columns that are never written (e.g. `Computer` used only by the schema) will
    not match — that is why a miss is a WARN, not an ERROR."""
    return re.search(rf"(?<![\w]){re.escape(col)}(?![\w])", query) is not None


def arm_expression_risk(value):
    return isinstance(value, str) and value.startswith("[") and not value.startswith("[[")


def rule_guid(res):
    for candidate in (res.get("name", ""), res.get("id", "")):
        m = GUID_RE.search(str(candidate))
        if m:
            return m.group(0).lower()
    return None


def check_resource_members(res, f):
    extra = sorted(set(res) - ARM_RESOURCE_MEMBERS - {"_source"})
    if "id" in extra:
        f.warn("id", "resource-level 'id' (from a portal export) is not an ARM template member - Sentinel > "
                     "Analytics > Import ignores it, but 'Deploy a custom template' / az deployment can reject it; drop it")
        extra.remove("id")
    if extra:
        f.warn("resource", f"not an ARM template resource member: {extra}")


def check_saved_search(res, f):
    """Hunting query (savedSearches): deployed by custom template, not by Analytics > Import."""
    check_resource_members(res, f)
    p = res.get("properties") or {}
    for key in ("category", "displayName", "query"):
        if not p.get(key):
            f.error(key, f"{key} is required")
    if "eTag" in p or "etag" in p:
        f.error("properties.eTag", "etag belongs on the resource, not in properties (API 2020-08-01+); "
                                   "use resource-level \"etag\": \"*\" to overwrite an existing query")
    unknown = sorted(set(p) - SAVED_SEARCH_PROPERTIES - {"eTag", "etag"})
    if unknown:
        f.error("properties", f"not a savedSearches property: {unknown}")
    if p.get("category") and p["category"] != "Hunting Queries":
        f.warn("category", f"{p['category']!r} - Sentinel Hunting only lists category 'Hunting Queries'")
    for key in ("displayName", "query"):
        if arm_expression_risk(p.get(key)):
            f.error(key, "string starts with '[' - ARM evaluates it as an expression; escape as '[[' or reword")
    query = p.get("query") or ""
    if len(query) > MAX_QUERY_CHARS:
        f.warn("query", f"{len(query)} chars - long hunts are fine here, but cannot become a rule as is")
    tags = p.get("tags") or []
    if not all(isinstance(t, dict) and isinstance(t.get("name"), str) and isinstance(t.get("value"), str)
               for t in tags):
        f.error("tags", "tags must be a list of {name, value} strings")
        return
    tagmap = {t["name"]: t["value"] for t in tags}
    for t in filter(None, (tagmap.get("tactics") or "").split(",")):
        if t.strip() not in TACTICS:
            f.error("tags.tactics", f"unknown tactic {t.strip()!r}")
    for t in filter(None, (tagmap.get("techniques") or "").split(",")):
        if not (TECHNIQUE_RE.match(t.strip()) or SUBTECHNIQUE_RE.match(t.strip())):
            f.error("tags.techniques", f"{t.strip()!r} is not a technique id")
    if "tactics" not in tagmap:
        f.warn("tags", "no 'tactics' tag - the hunt shows without MITRE mapping")


def template_findings(path):
    """Template-level issues: non-ARM root members, rules and hunts mixed in one file."""
    if path.lower().endswith((".yaml", ".yml")):
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not (isinstance(data, dict) and "resources" in data):
        return None
    f = Findings("<template>")
    extra = sorted(set(data) - ARM_ROOT_MEMBERS)
    if extra:
        f.error("template", f"not an ARM template root member: {extra}")
    types = {"rule" if "/alertRules" in str(r.get("type", "")) else "hunt" if r.get("type") == SAVED_SEARCH_TYPE
             else "other" for r in data["resources"]}
    if {"rule", "hunt"} <= types:
        f.warn("template", "analytics rules and hunting queries in one file: Analytics > Import takes only the "
                           "rules - ship hunts as their own template (Deploy a custom template)")
    return f if f.items else None


def check_rule(res, f):
    p = res.get("properties") or {}
    kind = res.get("kind")
    query = p.get("query") or ""
    is_yaml = res.get("_source") == "yaml"

    if not is_yaml:
        check_resource_members(res, f)
        api = str(res.get("apiVersion", ""))
        for prop, since in PREVIEW_ONLY_PROPERTIES.items():
            if p.get(prop) and not (api.endswith("-preview") and api >= since):
                f.error("apiVersion", f"{prop} is set but apiVersion {api!r} does not have it (no GA version "
                                      f"does) - use {since}-preview or a later -preview version")
        unknown = sorted(set(p) - SCHEDULED_PROPERTIES)
        if unknown:
            f.warn("properties", f"not a documented alert-rule property: {unknown}")

    if kind not in ("Scheduled", "NRT"):
        f.error("kind", f"kind must be Scheduled or NRT, got {kind!r}")
    if not p.get("displayName"):
        f.error("displayName", "displayName is required")
    if "enabled" not in p:
        f.error("enabled", "enabled (bool) is required")
    elif p.get("enabled") is True:
        f.warn("enabled", "rule imports ENABLED - import packs disabled and enable after a Logs test")

    # ARM expression hazard: a string starting with '[' is evaluated by ARM
    for key in ("displayName", "description", "query"):
        if arm_expression_risk(p.get(key)):
            f.error(key, "string starts with '[' - ARM evaluates it as an expression; escape as '[[' or reword")

    # severity
    sev = p.get("severity")
    if sev not in SEVERITIES:
        f.error("severity", f"severity must be one of {sorted(SEVERITIES)}, got {sev!r} (there is no Critical)")

    # scheduling
    if kind == "Scheduled":
        freq, period = p.get("queryFrequency"), p.get("queryPeriod")
        fs, ps = iso_seconds(freq), iso_seconds(period)
        if fs is None:
            f.error("queryFrequency", f"not an ISO 8601 duration: {freq!r}")
        if ps is None:
            f.error("queryPeriod", f"not an ISO 8601 duration: {period!r}")
        if fs is not None and not (MIN_SCHEDULE_SECONDS <= fs <= MAX_SCHEDULE_SECONDS):
            f.error("queryFrequency", f"{freq} outside 5 minutes - 14 days")
        if ps is not None and not (MIN_SCHEDULE_SECONDS <= ps <= MAX_SCHEDULE_SECONDS):
            f.error("queryPeriod", f"{period} outside 5 minutes - 14 days")
        if fs is not None and ps is not None:
            if fs > ps:
                f.error("queryPeriod", f"queryFrequency {freq} is longer than queryPeriod {period}")
            if fs > 3600 and ps > MAX_PERIOD_WHEN_FREQ_OVER_1H_SECONDS:
                f.error("queryPeriod", f"frequency over 1h limits the period to 48h (have {human(ps)})")
        if p.get("triggerOperator") not in ("GreaterThan", "LessThan", "Equal", "NotEqual", "gt", "lt", "eq", "ne", None):
            f.error("triggerOperator", f"unknown operator {p.get('triggerOperator')!r}")
        agg = (p.get("eventGroupingSettings") or {}).get("aggregationKind")
        if agg is not None and agg not in AGGREGATION_KINDS:
            f.error("eventGroupingSettings.aggregationKind", f"must be one of {sorted(AGGREGATION_KINDS)}, got {agg!r}")
    else:  # NRT
        for k in ("queryFrequency", "queryPeriod", "eventGroupingSettings"):
            if k in p and p[k] is not None:
                f.error(k, "not allowed on an NRT rule")
        if re.search(r"\b(join|union|externaldata)\b", query):
            f.error("query", "NRT rules cannot use join / union / externaldata")

    sup = p.get("suppressionDuration")
    if sup is None and not is_yaml:
        f.error("suppressionDuration", "required (PT5H is the portal default)")
    elif sup is not None and iso_seconds(sup) is None:
        f.error("suppressionDuration", f"not an ISO 8601 duration: {sup!r}")

    # query
    if not query:
        f.error("query", "query is empty")
    else:
        if len(query) > MAX_QUERY_CHARS:
            f.error("query", f"{len(query)} chars, limit {MAX_QUERY_CHARS} (move shared logic into a saved function)")
        if re.search(r"\bsearch\s+\*", query) or re.search(r"\bunion\s+\*", query):
            f.error("query", "'search *' / 'union *' are not allowed in analytics rules")
        if "{{" in query:
            f.error("query", "unresolved '{{' template placeholder in the query")
        for a, b in ("()", "[]", "{}"):
            if query.count(a) != query.count(b):
                f.warn("query", f"unbalanced {a}{b}: {query.count(a)} vs {query.count(b)} (strings/comments may explain it)")
        if re.search(r"\bbag_unpack\(", query) and "column_ifexists" not in query:
            f.warn("query", "bag_unpack without column_ifexists: a missing column fails the rule at run time")

    # MITRE
    tactics = p.get("tactics") or []
    for t in tactics:
        if t not in TACTICS:
            f.error("tactics", f"unknown tactic {t!r}")
    techniques = [str(t) for t in (p.get("techniques") or [])]
    subs = [str(t) for t in (p.get("subTechniques") or [])]
    for t in techniques:
        if not TECHNIQUE_RE.match(t):
            f.error("techniques", f"{t!r} does not match ^T\\d{{4}}$ (sub-techniques go in subTechniques)")
    for s in subs:
        if not SUBTECHNIQUE_RE.match(s):
            f.error("subTechniques", f"{s!r} does not match ^T\\d{{4}}\\.\\d{{3}}$")
        elif s.split(".")[0] not in techniques:
            f.warn("subTechniques", f"parent {s.split('.')[0]} of {s} is not listed in techniques")
    if not tactics:
        f.warn("tactics", "no tactic - MITRE coverage reporting will not see this rule")

    # alert details override
    ado = p.get("alertDetailsOverride") or {}
    for field, max_chars in (("alertDisplayNameFormat", MAX_DISPLAY_FORMAT_CHARS),
                             ("alertDescriptionFormat", MAX_DESCRIPTION_FORMAT_CHARS)):
        v = ado.get(field)
        if not v:
            continue
        where = f"alertDetailsOverride.{field}"
        phs = PLACEHOLDER_RE.findall(v)
        if len(phs) > MAX_FORMAT_PLACEHOLDERS:
            f.error(where, f"{len(phs)} placeholders, limit {MAX_FORMAT_PLACEHOLDERS}: {phs} "
                           f"- move the rest to customDetails or entities")
        if len(v) > max_chars:
            f.error(where, f"{len(v)} chars, limit {max_chars}")
        if arm_expression_risk(v):
            f.error(where, "starts with '[' - ARM expression hazard")
        for ph in phs:
            if ph != ph.strip() or not re.match(r"^\w+$", ph.strip()):
                f.error(where, f"placeholder {{{{{ph}}}}} must be a bare column name with no spaces")
            elif ph.startswith("_"):
                f.warn(where, f"{{{{{ph}}}}} references a system column; extend a plain alias and use that")
            elif query and not column_in_query(ph, query):
                f.warn(where, f"column {ph!r} not found in the query text - must be in the final output")
    for col_field in ("alertSeverityColumnName", "alertTacticsColumnName"):
        col = ado.get(col_field)
        if col and query and not column_in_query(col, query):
            f.warn(f"alertDetailsOverride.{col_field}", f"column {col!r} not found in the query text")
    sev_col = ado.get("alertSeverityColumnName")
    if sev_col and re.search(r'"Critical"', query):
        # tolerate the common internal scale: the override column is assigned on a line that
        # also mentions "Critical" (e.g. AlertSeverity = iff(Severity == "Critical", "High", Severity))
        maps_it = any(re.search(rf"\b{re.escape(sev_col)}\s*=", ln) and "Critical" in ln
                      for ln in query.splitlines())
        if not maps_it:
            f.warn("alertDetailsOverride.alertSeverityColumnName",
                   "query emits \"Critical\" - not a valid alert severity; map it to High in the override column")
    for dp in ado.get("alertDynamicProperties") or []:
        prop = dp.get("alertProperty")
        if prop not in DYNAMIC_PROPERTIES:
            f.error("alertDetailsOverride.alertDynamicProperties", f"unknown alertProperty {prop!r}")
        if prop == "ProductName":
            f.warn("alertDetailsOverride.alertDynamicProperties",
                   "overriding ProductName drops Microsoft-source alerts in the Defender portal")

    # custom details
    cd = p.get("customDetails") or {}
    if len(cd) > MAX_CUSTOM_DETAILS:
        f.error("customDetails", f"{len(cd)} entries, limit {MAX_CUSTOM_DETAILS}")
    for k, v in cd.items():
        if len(k) > MAX_CUSTOM_DETAIL_KEY_CHARS or not re.match(r"^[A-Za-z0-9]+$", k):
            f.error("customDetails", f"key {k!r} must be alphanumeric and at most {MAX_CUSTOM_DETAIL_KEY_CHARS} chars")
        if not isinstance(v, str) or not v:
            f.error("customDetails", f"value for {k!r} must be a column name")
            continue
        if v.startswith("_"):
            f.warn("customDetails", f"{k} -> {v}: system column; extend a plain alias and use that")
        elif query and not column_in_query(v, query):
            f.warn("customDetails", f"{k} -> {v}: column not found in the query text")

    # entity mappings
    ems = p.get("entityMappings") or []
    mapped_types = []
    if len(ems) > MAX_ENTITY_MAPPINGS:
        f.error("entityMappings", f"{len(ems)} mappings, limit {MAX_ENTITY_MAPPINGS}")
    if not ems:
        f.warn("entityMappings", "no entity mapping - incidents will have no entities and grouping by entity is impossible")
    for i, em in enumerate(ems):
        et = em.get("entityType")
        where = f"entityMappings[{i}]"
        if et not in ENTITY_IDENTIFIERS:
            f.error(where, f"unknown entityType {et!r}")
        else:
            mapped_types.append(et)
        fms = em.get("fieldMappings") or []
        if not (1 <= len(fms) <= MAX_FIELD_MAPPINGS_PER_ENTITY):
            f.error(where, f"{len(fms)} fieldMappings, must be 1-{MAX_FIELD_MAPPINGS_PER_ENTITY}")
        for fm in fms:
            ident, col = fm.get("identifier"), fm.get("columnName")
            if et in ENTITY_IDENTIFIERS and ident not in ENTITY_IDENTIFIERS[et]:
                f.error(where, f"identifier {ident!r} is not valid for {et} "
                               f"(valid: {sorted(ENTITY_IDENTIFIERS[et])})")
            if not col:
                f.error(where, "fieldMapping without columnName")
            elif query and not column_in_query(col, query):
                f.warn(where, f"column {col!r} for {et}.{ident} not found in the query text")

    # incident grouping
    ic = p.get("incidentConfiguration") or {}
    gc = ic.get("groupingConfiguration") or {}
    if gc and gc.get("enabled"):
        lb = gc.get("lookbackDuration")
        lbs = iso_seconds(lb)
        if lbs is None:
            f.error("groupingConfiguration.lookbackDuration", f"not an ISO 8601 duration: {lb!r}")
        elif not (MIN_GROUPING_LOOKBACK_SECONDS <= lbs <= MAX_GROUPING_LOOKBACK_SECONDS):
            f.error("groupingConfiguration.lookbackDuration", f"{lb} outside 5 minutes - 7 days")
        mm = gc.get("matchingMethod")
        if mm not in MATCHING_METHODS:
            f.error("groupingConfiguration.matchingMethod", f"must be one of {sorted(MATCHING_METHODS)}, got {mm!r}")
        ge = gc.get("groupByEntities") or []
        ga = gc.get("groupByAlertDetails") or []
        gcd = gc.get("groupByCustomDetails") or []
        if mm == "Selected" and not (ge or ga or gcd):
            f.error("groupingConfiguration", "matchingMethod Selected needs at least one groupBy* entry")
        for e in ge:
            if e not in mapped_types:
                f.error("groupingConfiguration.groupByEntities",
                        f"{e!r} is not an entity type mapped by this rule {sorted(set(mapped_types))}")
        for a in ga:
            if a not in GROUP_BY_ALERT_DETAILS:
                f.error("groupingConfiguration.groupByAlertDetails", f"{a!r} not in {sorted(GROUP_BY_ALERT_DETAILS)}")
        for c in gcd:
            if c not in cd:
                f.error("groupingConfiguration.groupByCustomDetails", f"{c!r} is not a customDetails key of this rule")


def check_template(resources):
    results = []
    seen = {}
    for res in resources:
        p = res.get("properties") or {}
        label = p.get("displayName") or res.get("name") or "<unnamed>"
        f = Findings(label)
        guid = rule_guid(res)
        if guid is None:
            f.error("name", "resource name does not contain a rule GUID")
        elif guid in seen:
            f.error("name", f"GUID {guid} is also used by {seen[guid]!r}")
        else:
            seen[guid] = label
        if res.get("type") == SAVED_SEARCH_TYPE:
            check_saved_search(res, f)
        else:
            check_rule(res, f)
        results.append(f)
    return results


def main():
    ap = argparse.ArgumentParser(description="Lint Sentinel analytics-rule templates against API limits")
    ap.add_argument("template", help="ARM template JSON, resource list JSON, or rule YAML")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()

    resources = load_resources(args.template)
    if not resources:
        print("No alertRules or savedSearches resources found.", file=sys.stderr)
        return 2
    results = check_template(resources)
    tf = template_findings(args.template)
    if tf:
        results.insert(0, tf)
    n_err = sum(len(r.errors) for r in results)
    n_warn = sum(len(r.warnings) for r in results)

    if args.json:
        print(json.dumps([{"rule": r.rule, "findings": [
            {"level": lvl, "where": w, "message": m} for lvl, w, m in r.items]} for r in results], indent=2))
    else:
        for r in results:
            status = "FAIL" if r.errors else ("WARN" if r.warnings else "ok")
            print(f"[{status:4s}] {r.rule}")
            for lvl, where, msg in r.items:
                print(f"         {lvl:5s} {where}: {msg}")
        print(f"\n{len(resources)} resource(s), {n_err} error(s), {n_warn} warning(s)")
        if n_err == 0:
            print("Offline checks passed. Still required: run each query in Logs on the target "
                  "workspace (KQL is validated against the workspace at create time).")
    failed = n_err > 0 or (args.strict and n_warn > 0)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

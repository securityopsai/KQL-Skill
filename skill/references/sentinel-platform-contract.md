# Sentinel Scheduled-Rule Platform Contract (import / deployment validation)

What the Sentinel API checks when a scheduled analytics rule is created or updated — by
ARM template, Bicep, Terraform, REST, the Repositories connector, or "Import" in the
portal. A rule that fails any of these is rejected at deployment time, usually with a
`BadRequest` that names the property. Everything here applies equally to a hand-written
template and to a portal export you edited: the export imported fine because the portal
wizard enforced these limits when the rule was first saved; your edits are not checked
until the API sees them.

Run `scripts/sentinel_template_lint.py <template.json>` before every import. It checks
every limit in this file that can be checked offline. The one thing it cannot check is
KQL semantics against your workspace — see "KQL is validated at create time" below.

## Alert details override (`alertDetailsOverride`)

| Field | Limit | Why it bites |
|---|---|---|
| `alertDisplayNameFormat` | **max 3 `{{Column}}` placeholders**, max 256 chars | The most common import failure after an edit. A fourth placeholder fails the whole deployment. |
| `alertDescriptionFormat` | **max 3 placeholders**, max 5000 chars | Same. Count placeholders per field, not per rule. |
| placeholder syntax | `{{ColumnName}}` exactly — no spaces inside the braces | `{{ Column }}` is not resolved and falls back to the rule default silently. |
| placeholder column | must be a column in the query **output** | Project it; a column that exists mid-query but is dropped by `summarize`/`project` resolves to empty. |
| `alertSeverityColumnName` | values must be `Informational`, `Low`, `Medium`, `High` | **There is no `Critical`.** Keep an internal severity scale if you like, but map it to the enum for the override column; unknown values fall back to the rule severity silently. |
| `alertTacticsColumnName` | values from the tactics enum below | same fallback behaviour |
| `alertDynamicProperties[].alertProperty` | `AlertLink`, `ConfidenceLevel`, `ConfidenceScore`, `ExtendedLinks`, `ProductComponentName`, `ProductName`, `ProviderName`, `RemediationSteps`, `Techniques`, `SubTechniques` | Do **not** override `ProductName` for Microsoft sources when onboarded to the Defender portal — alerts are dropped from XDR. |
| runtime | 50 distinct values per overridden field per run; above that all customisations are dropped for that run | aggregate before you alert |

When you have more than three things to say: put the extra columns in `customDetails`
or map them as entities. Entities (Host, Account, IP) are already shown on the incident,
so the format should carry what entities cannot: reason, detail, count, severity text.

## Custom details (`customDetails`)

- **max 20 key/value pairs** per rule
- key: **max 20 characters**, alphanumeric — it becomes a field name in `ExtendedProperties`
- value: a column name in the query output. Avoid underscore-prefixed system columns
  (`_ResourceId`, `_ItemId`) — `extend ResourceId = _ResourceId` and reference that
- runtime: 50 values per detail, 2 KB combined per alert; dynamic columns are
  stringified — `tostring()` arrays yourself so you control the format

## Entity mappings (`entityMappings`)

- **max 10 entity mappings** per rule, **1–3 `fieldMappings`** per entity
- `entityType` enum: `Account`, `Host`, `IP`, `URL`, `FileHash`, `File`, `Process`,
  `AzureResource`, `CloudApplication`, `DNS`, `RegistryKey`, `RegistryValue`,
  `SecurityGroup`, `Mailbox`, `MailCluster`, `MailMessage`, `SubmissionMail`, `Malware`
- identifiers must be valid **for that entity type**. Common ones:
  - Account: `Name`, `FullName`, `NTDomain`, `DnsDomain`, `UPNSuffix`, `Sid`, `AadUserId`, `AadTenantId`, `PUID`, `ObjectGuid`, `DisplayName`, `IsDomainJoined`, `CloudAppAccountId`
  - Host: `HostName`, `FullName`, `NTDomain`, `DnsDomain`, `NetBiosName`, `AzureID`, `OMSAgentID`, `OSFamily`, `OSVersion`, `IsDomainJoined`
  - IP: `Address` — URL: `Url` — DNS: `DomainName` — AzureResource: `ResourceId`
  - File: `Directory`, `Name` — FileHash: `Algorithm`, `Value`
  - Process: `ProcessId`, `CommandLine`, `ElevationToken`, `CreationTimeUtc`
  - CloudApplication: `AppId`, `Name`, `InstanceName`
  - RegistryKey: `Hive`, `Key` — RegistryValue: `Name`, `Value`, `ValueType`
  - SecurityGroup: `DistinguishedName`, `SID`, `ObjectGuid` — Malware: `Name`, `Category`
  - Mailbox: `MailboxPrimaryAddress`, `DisplayName`, `Upn`, `ExternalDirectoryObjectId`, `RiskLevel`
- `Account.Name` + `Account.NTDomain` (or `FullName` alone) and `Host.HostName` +
  `Host.DnsDomain` (or `FullName` alone) are the pairs that let Sentinel resolve the
  entity to a UEBA/Defender identity. Mapping only `Name` gives you a text label.
- runtime: 500 entities per alert, 64 KB — divided equally among mapped entity types

## Incident grouping (`incidentConfiguration.groupingConfiguration`)

- `lookbackDuration`: **5 minutes – 7 days** (ISO 8601, e.g. `PT5H`, `P1D`)
- `matchingMethod`: `AllEntities`, `AnyAlert`, `Selected`
- `Selected` needs at least one of `groupByEntities`, `groupByAlertDetails`,
  `groupByCustomDetails` non-empty
- `groupByEntities` may only name entity types that **this rule maps**
- `groupByCustomDetails` may only name keys defined in **this rule's** `customDetails`
- `groupByAlertDetails` ⊆ `DisplayName`, `Severity`
- `reopenClosedIncident` is ignored once Sentinel is onboarded to the Defender portal
- 150 alerts per incident; the 151st opens a new incident with the same details

## Scheduling

- `queryFrequency` and `queryPeriod`: **5 minutes – 14 days**, ISO 8601 (`PT1H`, `P7D`)
- `queryFrequency` ≤ `queryPeriod`
- frequency longer than one hour limits the period to **48 hours**; hourly or faster
  rules may look back the full 14 days
- `suppressionDuration` required (`PT5H` is the portal default) with `suppressionEnabled`
- Sentinel runs the query 5 minutes after the scheduled time to absorb ingestion delay.
  Pair `queryPeriod` with an `ingestion_time() > ago(<frequency>)` filter so each event
  alerts exactly once regardless of ingestion lag — see `kql-performance.md`.

## MITRE fields

- `tactics` enum: `Reconnaissance`, `ResourceDevelopment`, `InitialAccess`, `Execution`,
  `Persistence`, `PrivilegeEscalation`, `DefenseEvasion`, `CredentialAccess`,
  `Discovery`, `LateralMovement`, `Collection`, `Exfiltration`, `CommandAndControl`,
  `Impact`, `PreAttack`, `ImpairProcessControl`, `InhibitResponseFunction`
- `techniques`: `^T\d{4}$` only — **a sub-technique in `techniques` is rejected**
- `subTechniques`: `^T\d{4}\.\d{3}$`; list the parent technique in `techniques` too
- Rule YAML (Azure-Sentinel repo schema) uses `relevantTechniques` and accepts
  sub-techniques there; the conversion to ARM splits them. Do that split yourself when
  you build ARM directly.

## Severity, kind, enabled

- `severity`: `Informational`, `Low`, `Medium`, `High` — no `Critical`
- `kind`: `Scheduled` (this file) or `NRT` (no `queryFrequency`/`queryPeriod`,
  no `eventGroupingSettings`; single-table, no `join`/`union`/`externaldata`)
- `eventGroupingSettings.aggregationKind`: `SingleAlert` or `AlertPerResult`
  (`AlertPerResult` caps at 150 alerts per run)
- Import packs **disabled** and enable one rule at a time after a Logs test — the
  original export you were handed almost certainly had `"enabled": false` for that reason

## The query itself

- 1 – 10,000 characters; no `search *` or `union *`
- **KQL is validated at create time**, semantically, against the target workspace: a
  table or saved function that does not exist there, a typo in a column, `project` of a
  `bag_unpack` column that is missing (`column_ifexists` guards it) — all fail the
  deployment, not the first run. "It parses in my editor" is not the bar; "it ran in Logs
  on the target workspace" is.
- every column named by `alertDetailsOverride`, `customDetails`, `entityMappings` must be
  in the **final** output. After a `summarize`, re-`extend` anything you dropped.
- `now()` in a scheduled rule means the scheduled run time; `TimeGenerated` on your
  output rows drives the alert `StartTime`/`EndTime` — synthesise one (`TimeGenerated = now()`)
  when you aggregate it away

## ARM template mechanics

- A JSON string beginning with `[` is an **ARM expression** and is evaluated. A query,
  display name or format that starts with `[` must be escaped as `[[`. Starting the query
  with a `//` comment line avoids the problem entirely.
- The resource name GUID **is** the rule identity. Reuse it to update a rule in place;
  a new rule needs a new GUID (deterministic `uuid5(namespace, "<pack>/<rule-slug>")`
  keeps rebuilds stable). Two resources with the same GUID in one template fail.
- `apiVersion`: **`subTechniques` and `sentinelEntitiesMappings` exist only in the
  `-preview` API versions** (`subTechniques` from `2023-12-01-preview`). **No GA version has
  them**: `2024-03-01`, `2024-09-01`, `2025-03-01`, `2025-06-01` and `2025-09-01` all
  omit them. A template that sets either one needs a preview version.
  `2023-12-01-preview` is proven in this team's imports. A newer export can carry a GA
  version (the EXO export had `2024-09-01`), so "keep the export's version" is wrong as
  soon as you add sub-techniques. Lint flags this as an ERROR.
- `"name"` and the `parameters('workspace')` wiring from a portal export are correct —
  copy them, do not re-derive them. **Drop the resource-level `"id"`.** Sentinel >
  Analytics > Import ignores it, but it is not an ARM template resource member, so the
  same file deployed through *Deploy a custom template* (the portal GUI) or `az
  deployment` can be rejected. Without it, the file works both ways. Lint flags it as a
  WARN. Keep the template root to `$schema`, `contentVersion`, `parameters` and
  `resources`, as the export has it.
- `properties` must hold only documented members (checked against
  learn.microsoft.com/azure/templates/microsoft.securityinsights/alertrules for the
  chosen version). An unknown member is either dropped silently or rejected, and you
  can't tell which from your laptop.
- `templateVersion` / `alertRuleTemplateName` are for rules created from a content-hub
  template; leave `null` for custom rules

## Hunting queries (`savedSearches`) – never ship hunts as disabled rules

A "hunt-only" rule (scheduled, disabled, `createIncident: false`) is neither monitoring nor a
usable hunt. Ship hunts as Sentinel hunting queries, in their **own** template:

```json
{
  "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
  "apiVersion": "2020-08-01",
  "name": "[concat(parameters('workspace'), '/<uuid5 GUID>')]",
  "etag": "*",
  "properties": {
    "category": "Hunting Queries",
    "displayName": "UC-<PACK>-<nnn>-<Txxxx> - <title>",
    "query": "// ...",
    "version": 2,
    "tags": [
      {"name": "description", "value": "..."},
      {"name": "tactics", "value": "Exfiltration,DefenseEvasion"},
      {"name": "techniques", "value": "T1048,T1114.003"}
    ]
  }
}
```

- `etag` is a **resource** member. Inside `properties` it is not a documented member
  (some content-hub templates put `eTag` there – don't copy that). `"*"` lets a redeploy
  overwrite the existing hunt.
- `properties` ⊆ `category`, `displayName`, `query`, `version`, `tags`, `functionAlias`,
  `functionParameters`. `category` must be `Hunting Queries`, or Sentinel Hunting does not
  list the query.
- Tags are `{name, value}` strings. `tactics` uses the same enum as rules. `techniques` may
  include sub-techniques.
- No scheduling fields, and no `ago(RuleFrequency)` / `ingestion_time()` freshness gate in
  the query – a hunt is run by hand over a time range.
- **Deployment:** *Analytics > Import accepts alert rules only.* Hunts go in through the
  portal: search **Deploy a custom template** → *Build your own template in the editor* →
  *Load file* → resource group of the workspace, `workspace` = the workspace **name** →
  *Review + create*. The analytics files deploy this way too, once they have no `id`.
- Do not mix rules and hunts in one file. Ship one combined file per kind, plus one file
  per rule or hunt, so a team can import them one at a time. Lint warns on a mixed file.

## Deployment failure triage (in this order)

1. `scripts/sentinel_template_lint.py template.json` — fixes 90 % of post-edit failures
   (placeholder count, enum, missing column, grouping references).
2. Lint clean → it is the KQL. Paste the resolved query into **Logs on the target
   workspace** with the rule's `queryPeriod` as time range. A semantic error there is the
   deployment error.
3. Still failing → ARM level: `[` at the start of a string, duplicate GUID, wrong
   `apiVersion` (GA version + `subTechniques`), a portal-export `id` on a resource deployed
   as a custom template, a hunt file loaded into Analytics > Import, workspace parameter not
   passed (it is the workspace *name*), RBAC (needs Sentinel Contributor).
4. Read the error body: Sentinel names the offending property (`alertDescriptionFormat`,
   `entityMappings[1].fieldMappings`, ...). The ARM "deployment failed" wrapper hides it —
   expand the inner error or `az deployment group show --name <x> --query properties.error`.
5. Fix in the **source** (KQL file, build script, YAML) and regenerate the template.
   Hand-patching the exported JSON is how the next regeneration reintroduces the bug.

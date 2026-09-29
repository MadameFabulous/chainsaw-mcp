# Incident response report — {{case ID and descriptive title}}

| Document control | Value |
|---|---|
| Report version / document status | {{version; draft, interim or final}} |
| Incident status / as-of time | {{investigating, contained, recovered or unknown; ISO 8601 time}} |
| Prepared by / reviewed by | {{analyst; reviewer or not reviewed}} |
| Intended audience / handling | {{recipients; owner-supplied restrictions and TLP if supplied}} |
| Investigation question | {{question this report answers}} |
| Evidence mode | {{incident, curated-samples, filtered-export, or provenance unknown}} |
| Observed evidence window | {{start/end with timezone; distinguish from suspected incident window}} |
| Report date / timestamp convention | {{ISO 8601; source time fields and conversions}} |

## 1. Executive summary

{{Summarise the supported conclusion, affected scope, known business/data impact and current
response status. Cite key findings. State the most important uncertainty and decision/action
needed. Include the basis for incident severity or leave severity unassessed.}}

## 2. Scope, evidence and method

{{Describe requested scope, collection provenance, actually available hosts/files/channels,
processed scope and review depth. Record exclusions, collection and analysis dates, and
time filters. Explain scenario separation and any supported cross-file correlation.}}

| Scope / result reference | Files processed / available | Rule matches | Identifiable unique events | Unidentifiable records | Review coverage |
|---|---|---|---|---|---|
| {{scope and handle/export}} | {{counts or unknown}} | {{count or not applicable}} | {{count and scope}} | {{count}} | {{reviewed subset; outstanding work}} |

{{Explain overlaps and counting units. Describe tools/versions, rules/mapping, searches,
deduplication and relevant limits; link the reproducibility appendix if available.}}

## 3. Findings and impact

### F-001 — {{specific, evidence-supported finding title}}

| Assessment | Detail |
|---|---|
| Disposition | {{confirmed observation, supported inference, or unresolved lead}} |
| Affected scope | {{scenario, hosts/accounts/services/data; observed vs potentially affected}} |
| Analyst confidence / rationale | {{high, medium or low; evidence quality and gaps}} |
| Incident priority / rationale | {{organisation scale and business basis, or unassessed}} |
| Detection context | {{rule ID/name and level; separate from incident priority}} |
| Evidence | {{E-001 and other supporting records}} |

**Observed:** {{Key event fields and corroborating records, with evidence references.}}

**Assessment and alternatives:** {{Interpretation, competing benign explanations and what
supports or limits the conclusion. State unknown initial access/root cause explicitly.}}

**Impact:** {{Supported operational/data impact and its source; distinguish potential impact.
Do not infer exfiltration, financial loss or enterprise-wide compromise from a rule match.}}

**Tactics, techniques and procedures (TTPs)**

{{Map only supported behaviour. A tactic describes the adversary's objective; a technique
or sub-technique describes the method; a procedure describes its actual implementation in
this case. Mark uncertain mappings provisional or not assessed and explain the gap.}}

| Tactic ID / objective | Technique or sub-technique ID / name / reference | Observed procedure | Evidence | Mapping confidence / rationale |
|---|---|---|---|---|
| {{verified tactic and case-specific objective, or unknown}} | {{verified ATT&CK ID, name and source link, or provisional candidate}} | {{observed command/process chain/account/target/sequence; omit unsupported details}} | {{E-001 and corroborating records}} | {{high/medium/low; support and uncertainty}} |

{{Repeat the finding block as needed. If there are no supported findings, describe the checks
and their limits; distinguish a negative result from an incomplete investigation.}}

## 4. Timeline

{{Declare timezone and source timestamp fields. Keep separate tables per unrelated scenario.
List unknown-time events separately. Mark inferred ordering and clock uncertainty.}}

| Time (ISO 8601) | Scenario / host | Account / actor | Observed event or recorded response action | Finding / confidence | Evidence |
|---|---|---|---|---|---|
| {{time and offset}} | {{scope}} | {{actor or unknown}} | {{concise factual description}} | {{F-001; confidence}} | {{E-001 or response record}} |

## 5. Coverage, uncertainty and detection disposition

| Gap / uncertainty | Affected scope | Effect on conclusions | Follow-up |
|---|---|---|---|
| {{missing channel, filtering, parser warning, truncation, unreviewed batch, clock uncertainty}} | {{scope}} | {{what remains unknown}} | {{collection/check needed}} |

{{Describe continuity observations separately from evidence of log clearing or malicious
intent. Distinguish “not observed within reviewed evidence”, “unknown”, and “not assessed”.}}

| Detection / lead | Disposition | Evidence and reason |
|---|---|---|
| {{rule/lead and scope}} | {{benign explained, duplicate, unresolved or unreviewed}} | {{supporting context; missing verification}} |

## 6. Response actions and recommendations

{{Separate evidenced actions taken from proposed work. Record containment/eradication/recovery
status and verification, or state not assessed.}}

| Action ID / phase | Action and finding reference | Status | Owner | Performed time or target date | Verification / evidence |
|---|---|---|---|---|---|
| {{A-001; containment/eradication/recovery/follow-up}} | {{action; F-001; priority/rationale}} | {{proposed/in progress/completed/verified}} | {{owner or unassigned}} | {{time or not agreed}} | {{completion record or success criterion}} |

{{Record outstanding decisions and next update if agreed. For a post-incident review, include
what helped/hindered response and link contributing factors and lessons to tracked actions.}}

## Appendix A. Evidence register

{{Retain original source identities in a restricted register if the shared report uses
redacted aliases. Record evidence custody/collection details only when actually available.}}

| Evidence ID | Scenario / full source path | Host / channel / provider | Event ID / EventRecordID | Original timestamp / relevant fields | Saved attachment / lookup |
|---|---|---|---|---|---|
| {{E-001}} | {{scenario and path}} | {{values; preserve missing/null}} | {{values or artefact-specific locator}} | {{original time and key fields}} | {{attachment; handle and lookup details}} |

| Attachment | Purpose / scope | Collection or export time | Hash algorithm / digest / time computed | Provenance / custody reference |
|---|---|---|---|---|
| {{relative link or case-store reference}} | {{original, complete export, selected excerpt or redacted copy}} | {{time}} | {{actual hash; acquisition vs export vs attachment hash}} | {{record or unknown}} |

## Appendix B. Indicators and detection opportunities

{{Include only when useful. Keep contextual observables distinct from validated indicators;
describe potential legitimate use. Defang network indicators in the shareable report.}}

| Value / type | Role and context | First / last observed (scope and timezone) | Confidence | Finding / evidence | Suggested use |
|---|---|---|---|---|---|
| {{defanged value/type}} | {{behaviour; malicious/suspicious/contextual}} | {{observed bounds}} | {{confidence and caveat}} | {{F-001 / E-001}} | {{hunt/detection proposal; validation needed}} |

## Appendix C. Reproducibility and references

{{List actual tool/version, rule/mapping and command/filter details, saved replay script and
manifest if available, MCP postprocessing and known replay limitations. Label unexecuted
plans as proposed work. Explain that export-time input hashes do not establish historical
input identity or chain of custody. Record missing dependencies and unavailable metadata.}}

{{Cite methodology sources actually used, including the ATT&CK domain and version or
retrieval date used for TTP mappings. Case conclusions remain supported by the evidence
register. Include document revision notes when updating an earlier report.}}

# Incident report preparation: source notes

Retrieved and checked: **2026-09-29**. Scope: defensible incident and investigation
reports prepared from Chainsaw findings, including reports with incomplete evidence.
The companion report template is a local synthesis, not an official government form.

## Verified primary sources

### 1. NIST SP 800-61 Rev. 3: current incident-response guidance

- [Publication record](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [Full publication](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf)
- Published April 2025. References below use **printed page numbers**; PDF viewer
  page numbers are eight higher.
- **RS.AN-03, p. 28:** establish the event sequence, involved assets and resources,
  and underlying causes. Supports a chronological account and evidence-based
  cause analysis; an unestablished cause remains unknown.
- **RS.AN-06 and RS.AN-07, p. 29:** record investigation actions, preserve integrity
  and provenance, safeguard records, and retain evidence according to organizational
  procedures. Supports a sources register and an analyst-action record.
- **RS.AN-08, pp. 29–30:** estimate and validate incident magnitude by examining
  known and other potential targets. Supports explicit scope and coverage limits;
  a small supplied log set cannot establish the whole organization's exposure.
- **RS.CO and RS.CO-02, p. 30:** distinguish coordination, notification, public
  communication, and information sharing; follow applicable reporting procedures.
  Supports identifying the report audience and purpose separately from distribution.
- **RC.RP-06, p. 34:** prepare an after-action report documenting the incident,
  response and recovery actions, and lessons learned. Supports those distinct
  sections in a final report, with unknown or incomplete actions stated as such.

### 2. CISA federal response playbooks: timeline and post-incident structure

- [Cybersecurity Incident & Vulnerability Response Playbooks, November 2021](https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
- The former `/sites/default/files/publications/` download redirected to the link
  above. The hosting path's 2024 date does not change the document's 2021 edition.
- **Post-Incident Activities, pp. 16–17:** document the incident, inform leadership,
  improve defenses, finalize reports, and conduct lessons learned. Supports a
  short decision-oriented summary followed by technical findings and improvements.
- **Coordination, p. 18, “Share IOCs, TTPs, data”:** updates include scope, timeline,
  indicators, impact, outstanding efforts, and estimated response milestones.
  Supports a status/as-of field and clearly identified changes in interim reports.
- **Appendix B, p. 28, step 4f:** the incident timeline records events, descriptions,
  occurrence times in UTC, impacts, and data sources. Supports a chronological
  timeline with a source reference on every row.
- **Appendix B, p. 34, step 10f:** the post-incident report gives a step-by-step
  review addressing who, what, where, why, and how. Steps 10i–10p cover lessons,
  process sufficiency, policy gaps, sharing, training, roles, and defensive gaps.
- The playbooks target U.S. federal civilian executive branch agencies. Do not
  copy their notification deadlines or agency-specific obligations into a general
  Chainsaw report as universal requirements.

### 3. CISA incident notification model: explicit reporting fields

- [Federal Incident Notification Guidelines](https://www.cisa.gov/federal-incident-notification-guidelines)
- This is a verified, publicly available **reporting-field model**, rather than
  merely an incident response plan. The page states an April 1, 2017 effective
  date and references NIST Rev. 2; describe its age and scope accurately.
- **“Submitting Incident Notifications,” steps 1–7:** functional impact,
  information impact, recoverability, first detection time, affected system/record/
  user counts, network location, and a follow-up contact.
- **Steps 9–11:** attack vectors, indicators/detection measures, and mitigation
  activities, when known. Supports impact, affected assets, indicators, and actions
  fields; contextual observations must not automatically become malicious IOCs.
- **“Notification Requirement”:** complete, validated information may be unavailable;
  provide the best estimate and update it. Supports draft/interim reports and
  explicit unknowns, estimates, and later corrections.
- **“Impact and Severity Assessment”:** operational, information, and recovery
  dimensions are assessed separately. Supports explaining impact and severity
  rationale; a detection rule's severity alone is insufficient business context.
- These are fields for notifications to CISA, not a universal final-report format.
  This skill neither submits notifications nor determines legal obligations.

### 4. NIST SP 800-61 Rev. 2: historical field checklist only

- [Publication and withdrawal record](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
- [Historical publication](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- **Withdrawn April 3, 2025; superseded by Rev. 3.** Do not call it current NIST
  guidance. Its detailed field list remains useful historical design input.
- **Appendix B.1–B.2, printed pp. 58–59:** reporter/handler, timestamps with time
  zones, incident status, description, affected resources, indicators, prioritization
  factors, response actions, evidence gathered, cause, cost, and business impact.
- The appendix explicitly describes suggested, non-exhaustive elements that each
  organization should tailor. Supports a consistent report record and optional
  fields, rather than requiring unavailable personal, financial, or business data.

### 5. FIRST Traffic Light Protocol 2.0: handling labels

- [Authoritative TLP 2.0 definitions and usage guidance](https://www.first.org/tlp/)
- **Section 1b–c:** labels use their exact forms without spaces; TLP is a sharing
  boundary, not a formal classification or an encryption/handling standard.
- **Sections 1f and 3:** the source is responsible for recipients understanding
  the sharing guidance, and label definitions explain when sources may use each.
  Use the source/owner's designated label; do not silently assign one for them.
- **Sections 1g–h:** preserve source restrictions; wider sharing requires the
  source's explicit permission. Do not invent or loosen a label while reporting.
- **Section 2b:** TLP-labeled documents put the label and additional restrictions
  in each page's header and footer; at least 12-point type and right alignment
  are recommendations. Markdown alone cannot enforce paginated headers/footers;
  inspect those in any later PDF or document export.
- **Section 3b:** `TLP:AMBER` includes need-to-know sharing with the recipient's
  organization and clients; `TLP:AMBER+STRICT` limits it to the organization.
  Do not describe these as interchangeable or choose a default on the user's behalf.

### 6. MITRE ATT&CK: tactics, techniques and procedures

- [ATT&CK FAQ](https://attack.mitre.org/resources/faq/), checked 2026-09-29.
- **“What are tactics/techniques/sub-techniques/procedures?”:** tactics describe the
  adversary's goal; techniques describe the method; sub-techniques refine the method;
  procedures describe specific implementations observed in use.
- **“What are the differences between sub-techniques and procedures?”:** a procedure
  may involve several techniques or sub-techniques. Supports recording the actual
  case behaviour alongside the appropriate mappings instead of repeating technique
  names as procedures.
- Local reporting adaptation: record tactic, technique/sub-technique ID and name,
  observed procedure, evidence references and mapping confidence. Verify mappings
  against the referenced ATT&CK domain/version or retrieved pages. Treat published
  procedure examples as comparisons; they do not establish this case's facts or actor.

## Formatting decisions synthesized for this repository

These are implementation choices informed by the sources above, not prescribed
government headings, a compliance certification, or an official reporting template.

| Report decision | Basis and local adaptation |
| --- | --- |
| Lead with a short executive summary | CISA leadership and impact focus; summarize assessment, observed scope, confidence, impact, and decisions needed. |
| Separate document status from incident status | CISA updates and NIST recovery criteria; “final report” must not imply successful recovery. |
| Include scope, evidence, method, and limitations | NIST provenance and magnitude; identify supplied files, time bounds, filters, failed reads, truncation, and missing telemetry. |
| Give findings stable IDs and evidence references | Local traceability design supporting NIST provenance; distinguish rule matches, reviewed observations, and analyst assessments. |
| Map tactics, techniques and observed procedures separately | MITRE ATT&CK definitions; connect each case-specific behaviour and proposed mapping to evidence and confidence. |
| Separate severity, confidence, and observed facts | Local analysis discipline; severity describes impact, confidence describes evidential support, and neither is a detection count. |
| Use a UTC event timeline with source references | CISA step 4f; preserve original timestamps/offsets and identify uncertainty or clock skew rather than silently correcting it. |
| Keep actions taken apart from recommendations | NIST RC.RP-06 and CISA lessons learned; record actual evidence of completion and add owners, priorities, and verification criteria to proposed work. |
| Keep raw event dumps in an appendix or linked artifact | Local readability choice; give the main narrative concise excerpts and stable artifact references. |
| Use explicit unknown / not provided / not assessed values | CISA permits incomplete initial information; avoid fabricated evidence, impact, root cause, ownership, or recovery claims. |
| Preserve handling instructions through export | FIRST TLP 2.0; a local report file is not an authorization to distribute it. |

## Research limits

- Official PDFs and HTML pages above were downloaded and their cited content read.
  No incident data was submitted to a reporting form.
- Australian Cyber Security Centre guidance/template pages timed out; New Zealand
  NCSC/CERT resources returned access errors. They are not evidence for this skill.
- No separately downloadable national-authority final-report form was verified.
  CISA's explicit notification fields and NIST's historical Appendix B provide
  concrete field models; the supplied local Markdown template combines them with
  current NIST and CISA post-incident guidance.
- The retrieved CISA documents contain older policy references. Recheck actual
  organizational and jurisdictional obligations before making a real notification;
  this research establishes report structure, not current legal deadlines.

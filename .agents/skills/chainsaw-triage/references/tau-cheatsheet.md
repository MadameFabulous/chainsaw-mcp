# Tau expressions for chainsaw_search

Format: `Field.Path: <expression>`. Paths are dotted JSON paths into the parsed document.
For EVTX: `Event.System.EventID`, `Event.System.Computer`, `Event.System.Channel`,
`Event.System.TimeCreated_attributes.SystemTime`, `Event.EventData.<Name>`.

| Expression | Meaning |
|---|---|
| `Event.System.EventID: =4624` | numeric equals (also `>`, `<`, `>=`, `<=`) |
| `Event.EventData.LogonType: =9` | numeric field |
| `Event.EventData.TargetUserName: iadmin*` | case-insensitive (`i` prefix) wildcard match |
| `Event.EventData.Image: *\\mimikatz.exe` | suffix wildcard (escape backslashes as `\\`) |
| `Event.EventData.CommandLine: i*-enc*` | contains, case-insensitive |
| `Event.EventData.IpAddress: 10.0.0.5` | exact string |
| `Event.EventData.SubjectLogonId: 0x3e7` | hex LogonId as string |
| `Event.System.Channel: Security` | channel filter |

Multiple `tau` entries are ANDed; set `match_any=true` for OR. `patterns` (regexes over
the whole document) can be mixed with `tau`.

Time bounding: `from_time` / `to_time` as `YYYY-MM-DDTHH:MM:SS` (UTC). The server sets
`timestamp_field` to the EVTX SystemTime automatically; override for JSON/XML evidence.

Typical pivots:

- Everything a LogonId did: `Event.EventData.SubjectLogonId: 0x1234ab` and again with
  `Event.EventData.TargetLogonId`.
- Process tree: `Event.EventData.ParentProcessGuid: {guid}` (Sysmon 1).
- Source host activity: `Event.EventData.IpAddress: 10.1.2.3` plus
  `Event.EventData.WorkstationName: iHOSTNAME`.
- Service installs in a window: `Event.System.EventID: =7045` with `from_time`/`to_time`.

import json
from pathlib import Path

from chainsaw_mcp.runner import RunResult
from chainsaw_mcp.tools._common import ToolContext
from chainsaw_mcp.tools.analyse import AnalyseTools
from chainsaw_mcp.tools.evidence import EvidenceTools


def test_gap_details_are_paged_and_diagnostics_preserved(settings):
    ctx = ToolContext(settings)

    class GapRunner:
        def run(self, args, **kwargs):
            return RunResult(
                args,
                0,
                json.dumps(
                    [
                        {"kind": "record_id", "path": "a.evtx", "detail": "x" * 10000}
                        for _ in range(100)
                    ]
                ),
                "[!] Failed to parse record\n" + "[+] info\n" * 100,
                0.1,
            )

    ctx.runner = GapRunner()
    raw = AnalyseTools(ctx).chainsaw_analyse_gaps(["host1/Security.evtx"])
    data = json.loads(raw)
    assert len(raw.encode()) <= 128 * 1024
    assert data["total"] == ctx.store.meta(data["handle"]).count == 100
    assert data["truncated"] is True
    assert data["diagnostics"]["parse_status"] == "incomplete"
    assert data["diagnostics"]["message_count"] == 101
    assert "filtered" in data["interpretation"]


def test_shimcache_and_srum_read_published_paths(settings):
    ctx = ToolContext(settings)

    class OutputRunner:
        def run(self, args, **kwargs):
            output = Path(args[args.index("--output") + 1])
            output.write_text("header\nvalue\n" if args[1] == "shimcache" else "é" * 100)
            return RunResult(args, 0, "", "", 0.1)

    ctx.runner = OutputRunner()
    tools = AnalyseTools(ctx)
    shim = json.loads(tools.chainsaw_analyse_shimcache("host1/notes.txt"))
    assert shim["preview"]["rows"] == ["value"]
    srum = json.loads(
        tools.chainsaw_analyse_srum("host1/notes.txt", "host1/notes.txt", preview_bytes=7)
    )
    assert len(srum["preview"].encode()) <= 7
    assert srum["bytes"] == 200
    assert not ctx.store._active


class CoverageRunner:
    def run(self, args, **kwargs):
        if args[0] == "dump":
            output = Path(args[args.index("--output") + 1])
            rows = [
                {
                    "Event": {
                        "System": {
                            "Channel": None,
                            "Provider_attributes": {"Name": "Microsoft-Windows-RPC"},
                            "EventID": 5,
                        }
                    }
                },
                {"Event": {"System": {"Channel": "Security", "EventID": 7}}},
            ]
            output.write_text("\n".join(json.dumps(r) for r in rows))
            return RunResult(args, 0, "", "[+] Done", 0.1)
        return RunResult(
            args,
            0,
            json.dumps(
                [
                    {
                        "path": "one.evtx",
                        "records_seen": 2,
                        "channels": [
                            {
                                "channel": "Security",
                                "records_seen": 1,
                                "event_ids": [{"event_id": 7, "count": 1}],
                            }
                        ],
                    }
                ]
            ),
            "[+] Done",
            0.1,
        )


def test_provider_coverage_counts_missing_channel_without_corruption(settings):
    ctx = ToolContext(settings)
    ctx.runner = CoverageRunner()
    data = json.loads(EvidenceTools(ctx).chainsaw_analyse_evtx(["host1/Security.evtx"]))
    assert data["records"] == 2
    assert data["by_provider"]["Microsoft-Windows-RPC"] == 1
    assert data["missing_metadata"] == {"channel": 1, "provider": 1, "event_id": 0}
    assert data["diagnostics"]["skipped_records"] is None
    assert data["diagnostics"]["parse_status"] == "unknown"
    assert ctx.store.page(data["handle"])["rows"][0]["records_seen"] == 2
    coverage = list(ctx.store.rows(data["coverage_handle"]))
    assert any(r.get("provider_name") == "Microsoft-Windows-RPC" for r in coverage)
    assert not ctx.store._active


def test_failed_outputs_release_reservations(settings):
    import pytest

    from chainsaw_mcp.runner import ChainsawError

    ctx = ToolContext(settings)

    class FailingRunner:
        def run(self, args, **kwargs):
            raise ChainsawError("failed")

    ctx.runner = FailingRunner()
    tools = AnalyseTools(ctx)
    for method, args in [
        (tools.chainsaw_analyse_shimcache, ["host1/notes.txt"]),
        (tools.chainsaw_analyse_srum, ["host1/notes.txt"] * 2),
    ]:
        with pytest.raises(ChainsawError):
            method(*args)
        assert not ctx.store._active


def test_analysis_byte_budget_with_huge_file_and_diagnostic(settings):
    ctx = ToolContext(settings)

    class HugeRunner(CoverageRunner):
        def run(self, args, **kwargs):
            result = super().run(args, **kwargs)
            if args[0] == "dump":
                return result
            return RunResult(
                args,
                0,
                json.dumps([{"path": "é" * 100000, "records_seen": 2, "channels": []}]),
                "[!] Warning " + "é" * 100000,
                0.1,
            )

    ctx.runner = HugeRunner()
    raw = EvidenceTools(ctx).chainsaw_analyse_evtx(["host1/Security.evtx"])
    data = json.loads(raw)
    assert len(raw.encode()) <= 128 * 1024
    assert data["per_file"] == [] and data["next_offset"] == 0
    assert len(list(ctx.store.rows(data["diagnostics"]["handle"]))[0]["message"]) > 100000


def test_live_rpc_provider_coverage(tmp_path):
    import pytest

    from chainsaw_mcp.config import load_settings
    from tests.conftest import REPO, SAMPLES, VENDOR_BIN

    if not VENDOR_BIN.exists() or not SAMPLES.is_dir():
        pytest.skip("local binary and EVTX samples required")
    ctx = ToolContext(
        load_settings(
            {
                "CHAINSAW_HOME": str(REPO),
                "CHAINSAW_BIN": str(VENDOR_BIN),
                "CHAINSAW_EVIDENCE_ROOTS": str(SAMPLES),
                "CHAINSAW_OUTPUT_DIR": str(tmp_path / "out"),
                "CHAINSAW_CUSTOM_RULES_DIR": str(tmp_path / "rules"),
            }
        )
    )
    raw = EvidenceTools(ctx).chainsaw_analyse_evtx(
        [
            "Credential Access/etw_rpc_zerologon.evtx",
            "Credential Access/CA_PetiPotam_etw_rpc_efsr_5_6.evtx",
        ]
    )
    data = json.loads(raw)
    assert data["records"] == 29524
    assert data["by_provider"]["Microsoft-Windows-RPC"] == 29523
    assert data["missing_metadata"]["channel"] == 29524
    # The ETW header event has no provider Name; do not attribute it to RPC.
    assert data["missing_metadata"]["provider"] == 1
    assert data["coverage_status"] == "observed"
    assert len(raw.encode()) < 128 * 1024


def test_partial_dump_reports_incomplete_without_invented_skip_counts(settings):
    ctx = ToolContext(settings)

    class PartialRunner(CoverageRunner):
        def run(self, args, **kwargs):
            result = super().run(args, **kwargs)
            if args[0] == "dump":
                output = Path(args[args.index("--output") + 1])
                with output.open("a") as fh:
                    fh.write("\nnot json\n")
            return result

    ctx.runner = PartialRunner()
    data = json.loads(EvidenceTools(ctx).chainsaw_analyse_evtx(["host1/Security.evtx"]))
    assert data["coverage_status"] == "incomplete"
    assert data["diagnostics"]["parse_status"] == "incomplete"
    assert data["diagnostics"]["skipped_records"] is None
    assert data["diagnostics"]["coverage_records"] == 2
    assert not ctx.store._active

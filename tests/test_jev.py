from __future__ import annotations

import json
import subprocess
from dataclasses import replace

import httpx
import pytest

from chainsaw_mcp import jev
from chainsaw_mcp.config import load_settings
from chainsaw_mcp.result_budget import DEFAULT_MAX_BYTES
from chainsaw_mcp.server import annotations_for, build_server
from chainsaw_mcp.tools._common import ToolContext
from chainsaw_mcp.tools.jev import JevTools
from tests.test_server import call, payload


@pytest.fixture
def enabled(settings):
    return replace(settings, jev_enabled=True, jev_api_key="test-secret")


def seed(ctx, rows=None):
    handle, path = ctx.store.reserve()
    path.write_text(
        "\n".join(
            json.dumps(row)
            for row in (
                rows
                if rows is not None
                else [
                    {"name": "Test detection", "level": "high", "private": "do not send"},
                    {"name": "Another detection", "level": "low", "private": "do not send"},
                ]
            )
        )
    )
    ctx.store.commit(handle, tool="chainsaw_hunt", argv=[], inputs={})
    return handle


def answer(body):
    answers = {}
    for name, question in body["questions"].items():
        answers[name] = (
            {
                "type": "choice",
                "choice": "suspicious",
                "confidence": 0.9,
                "probabilities": {
                    "suspicious": 0.95,
                    "likely_benign": 0.02,
                    "insufficient_context": 0.03,
                },
            }
            if question["type"] == "choice"
            else {
                "type": "score",
                "score": 2.8,
                "confidence": 0.9,
                # The live API also returns the rubric it was given; it must be tolerated.
                "legend": dict(enumerate(jev.PRIORITIES)),
                "probabilities": {"0": 0, "1": 0, "2": 0.2, "3": 0.8},
            }
        )
    return {
        "model": "jev-test",
        "answers": answers,
        "usage": {"input_tokens": 12, "output_tokens": 3},
    }


def mock_api(monkeypatch, handler):
    original = httpx.Client
    monkeypatch.setattr(
        jev.httpx,
        "Client",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )


def test_projection_provenance_sorting_and_uncertainty(enabled, monkeypatch):
    ctx = ToolContext(enabled)
    handle = seed(ctx)
    before = ctx.store.data_path(handle).read_bytes()
    requests = []

    def handler(request):
        requests.append(request)
        assert str(request.url) == jev.ENDPOINT
        assert request.headers["Authorization"] == "Bearer test-secret"
        body = json.loads(request.content)
        assert body["state"]["records"] == {
            "row_0": {"rule": "Test detection"},
            "row_1": {"rule": "Another detection"},
        }
        assert len(body["questions"]) == 4
        # Jev does not see question IDs: each instruction must identify its source row.
        for name, question in body["questions"].items():
            row_id = name.rsplit("_", 1)[0]
            other_id = "row_1" if row_id == "row_0" else "row_0"
            assert f"state.records.{row_id}" in question["instructions"]
            assert f"state.records.{other_id}" not in question["instructions"]
        data = answer(body)
        data["answers"]["row_0_priority"].update(
            score=1, probabilities={"0": 0, "1": 1, "2": 0, "3": 0}
        )
        data["answers"]["row_1_classification"]["confidence"] = 0.2
        return httpx.Response(200, json=data)

    mock_api(monkeypatch, handler)
    result = json.loads(JevTools(ctx).chainsaw_jev_triage(handle, fields=["rule"]))
    assert len(requests) == 1
    assert result["request_bytes"] == len(requests[0].content)
    assert result["source_handle"] == handle and result["model"] == "jev-test"
    assert result["next_offset"] is None
    assert result["assessments"][0]["source_row_index"] == 1
    assert result["assessments"][0]["uncertain"]
    assert result["assessments"][0]["uncertain_reasons"] == ["low_classification_confidence"]
    assert not result["assessments"][1]["uncertain"]
    assert result["assessments"][1]["uncertain_reasons"] == []
    assert ctx.store.data_path(handle).read_bytes() == before
    assert len(ctx.store.list()) == 1


def test_disabled_and_missing_credentials(settings, enabled):
    server = build_server(settings)
    result = call(server, "chainsaw_jev_triage", {"handle": "res_0000000000000000"})
    assert result.is_error and "disabled" in result.content[0].text
    with pytest.raises(jev.JevError, match="TYPESAFE_API_KEY"):
        jev.evaluate(replace(enabled, jev_api_key=""), {"row_0": {}})


def test_mcp_bounds_invalid_handle_and_annotations(enabled, monkeypatch):
    def no_request(*args, **kwargs):
        pytest.fail("Should not make network requests")

    monkeypatch.setattr(jev, "evaluate", no_request)
    server = build_server(enabled)
    for args in [
        {"handle": "../../secret"},
        {"handle": "res_0000000000000000"},
        {"handle": "anything", "limit": 11},
        {"handle": "anything", "offset": -1},
        {"handle": "anything", "min_confidence": 1.1},
        {"handle": "anything", "fields": []},
    ]:
        assert call(server, "chainsaw_jev_triage", args).is_error
    annotations = annotations_for("chainsaw_jev_triage")
    # Evidence leaves the host and API usage is consumed: open-world, not read-only.
    assert annotations.open_world_hint and not annotations.read_only_hint
    assert not annotations.idempotent_hint and not annotations.destructive_hint


def test_empty_and_non_json_results(enabled, monkeypatch):
    ctx = ToolContext(enabled)
    handle = seed(ctx, [])
    monkeypatch.setattr(jev, "evaluate", lambda *_: pytest.fail("Unexpected API request"))
    assert not json.loads(JevTools(ctx).chainsaw_jev_triage(handle))["request_sent"]
    handle, path = ctx.store.reserve(".csv")
    path.write_text("header\nvalue\n")
    ctx.store.commit(handle, tool="chainsaw_analyse_srum", argv=[], inputs={}, fmt="csv")
    with pytest.raises(ValueError, match="not JSON rows"):
        JevTools(ctx).chainsaw_jev_triage(handle)


def test_pagination_and_insufficient_context(enabled, monkeypatch):
    server = build_server(enabled)
    handle = seed(server._chainsaw_ctx)

    def handler(request):
        body = json.loads(request.content)
        assert list(body["state"]["records"]) == ["row_1"]
        data = answer(body)
        data["answers"]["row_1_classification"].update(
            choice="insufficient_context",
            probabilities={"suspicious": 0.02, "likely_benign": 0.03, "insufficient_context": 0.95},
        )
        return httpx.Response(200, json=data)

    mock_api(monkeypatch, handler)
    result = payload(
        call(
            server,
            "chainsaw_jev_triage",
            {
                "handle": handle,
                "offset": 1,
                "limit": 1,
            },
        )
    )
    assert result["returned"] == 1 and result["next_offset"] is None
    assert result["assessments"][0]["source_row_index"] == 1
    assert result["assessments"][0]["uncertain"]
    assert result["assessments"][0]["uncertain_reasons"] == ["insufficient_context"]


@pytest.mark.parametrize(
    "choice, classification_confidence, priority_confidence, threshold, reasons",
    [
        ("suspicious", 0.8, 0.8, None, []),
        ("suspicious", 0.7, 0.8, None, ["low_classification_confidence"]),
        ("suspicious", 0.8, 0.7, None, ["low_priority_confidence"]),
        (
            "suspicious",
            0.7,
            0.7,
            None,
            ["low_classification_confidence", "low_priority_confidence"],
        ),
        ("insufficient_context", 0.8, 0.8, None, ["insufficient_context"]),
        (
            "insufficient_context",
            0.7,
            0.8,
            None,
            ["insufficient_context", "low_classification_confidence"],
        ),
        (
            "insufficient_context",
            0.8,
            0.7,
            None,
            ["insufficient_context", "low_priority_confidence"],
        ),
        (
            "insufficient_context",
            0.7,
            0.7,
            None,
            ["insufficient_context", "low_classification_confidence", "low_priority_confidence"],
        ),
        ("likely_benign", 0, 0, 0, []),
        ("insufficient_context", 0, 0, 0, ["insufficient_context"]),
        ("suspicious", 1, 1, 1, []),
        ("likely_benign", 0.5, 0.4, 0.5, ["low_priority_confidence"]),
    ],
)
def test_uncertainty_reasons_and_threshold_boundaries_over_mcp(
    enabled, monkeypatch, choice, classification_confidence, priority_confidence, threshold, reasons
):
    server = build_server(enabled)
    handle = seed(server._chainsaw_ctx, [{"name": "Boundary case"}])
    responses = []

    def handler(request):
        data = answer(json.loads(request.content))
        data["answers"]["row_0_classification"].update(
            choice=choice,
            confidence=classification_confidence,
            probabilities={label: 1 if label == choice else 0 for label in jev.CLASSIFICATIONS},
        )
        data["answers"]["row_0_priority"]["confidence"] = priority_confidence
        responses.append(data)
        return httpx.Response(200, json=data)

    mock_api(monkeypatch, handler)
    arguments = {"handle": handle}
    if threshold is not None:
        arguments["min_confidence"] = threshold
    result = payload(call(server, "chainsaw_jev_triage", arguments))
    assert len(responses) == 1
    assert result["min_confidence"] == (0.8 if threshold is None else threshold)
    assert result["failed"] == 0
    assessment = result["assessments"][0]
    assert assessment["uncertain_reasons"] == reasons
    assert assessment["uncertain"] is bool(reasons)
    assert assessment["classification"] == responses[0]["answers"]["row_0_classification"]
    assert assessment["priority"]["confidence"] == priority_confidence
    assert assessment["priority"]["score"] == 2.8


@pytest.mark.parametrize("status", [301, 401, 429, 500])
def test_http_errors_are_sanitized_and_not_retried(enabled, monkeypatch, status):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            status,
            text="test-secret sensitive evidence",
            headers={
                "Location": "https://example.invalid/steal",
            },
        )

    mock_api(monkeypatch, handler)
    with pytest.raises(jev.JevError, match=f"HTTP {status}") as error:
        jev.evaluate(enabled, {"row_0": {}})
    assert "test-secret" not in str(error.value) and len(seen) == 1


@pytest.mark.parametrize("failure", [httpx.ReadTimeout, httpx.ConnectError])
def test_transport_errors_are_sanitized(enabled, monkeypatch, failure):
    def handler(request):
        raise failure("test-secret sensitive evidence", request=request)

    mock_api(monkeypatch, handler)
    with pytest.raises(jev.JevError) as error:
        jev.evaluate(enabled, {"row_0": {}})
    assert "test-secret" not in str(error.value)


@pytest.mark.parametrize("fault", ["missing", "confidence", "score", "choice", "probability"])
def test_malformed_answers_fail_closed(enabled, monkeypatch, fault):
    def handler(request):
        data = answer(json.loads(request.content))
        if fault == "missing":
            data["answers"].pop("row_0_priority")
        elif fault == "confidence":
            data["answers"]["row_0_priority"]["confidence"] = float("nan")
        elif fault == "score":
            data["answers"]["row_0_priority"]["score"] = 99
        elif fault == "choice":
            data["answers"]["row_0_classification"]["choice"] = "other"
        else:
            data["answers"]["row_0_priority"]["probabilities"]["3"] = 2
        return httpx.Response(200, content=json.dumps(data))

    mock_api(monkeypatch, handler)
    result = jev.evaluate(enabled, {"row_0": {}})
    assert result["answers"] == {}
    assert "row_0" in result["errors"]


def test_contradictory_choice_fails_its_row(enabled, monkeypatch):
    ctx = ToolContext(enabled)
    handle = seed(ctx)

    def handler(request):
        data = answer(json.loads(request.content))
        data["answers"]["row_0_classification"]["choice"] = "likely_benign"
        return httpx.Response(200, json=data)

    mock_api(monkeypatch, handler)
    result = json.loads(JevTools(ctx).chainsaw_jev_triage(handle))
    assert result["failed"] == 1
    failed = result["assessments"][-1]
    assert failed["error"] == "choice_argmax"
    assert failed["classification"] is None and failed["priority"] is None
    assert "test-secret" not in json.dumps(result)
    assert "Test detection" not in json.dumps(result)


@pytest.mark.parametrize("selected", ["suspicious", "likely_benign"])
def test_choice_accepts_either_tied_maximum(enabled, monkeypatch, selected):
    def handler(request):
        data = answer(json.loads(request.content))
        data["answers"]["row_0_classification"].update(
            choice=selected,
            probabilities={"suspicious": 0.45, "likely_benign": 0.45, "insufficient_context": 0.1},
        )
        return httpx.Response(200, json=data)

    mock_api(monkeypatch, handler)
    result = jev.evaluate(enabled, {"row_0": {}})
    assert result["answers"]["row_0_classification"]["choice"] == selected


@pytest.mark.parametrize("score", [0, 3])
def test_contradictory_score_fails_before_triage_sorting(enabled, monkeypatch, score):
    ctx = ToolContext(enabled)
    handle = seed(ctx)

    def handler(request):
        data = answer(json.loads(request.content))
        # Mean is 2.8, mode is 3. Neither the mode nor an unrelated value is valid.
        data["answers"]["row_1_priority"]["score"] = score
        return httpx.Response(200, json=data)

    mock_api(monkeypatch, handler)
    result = json.loads(JevTools(ctx).chainsaw_jev_triage(handle))
    assert result["failed"] == 1
    assert result["assessments"][-1]["source_row_index"] == 1
    assert result["assessments"][-1]["error"] == "score_mean"


@pytest.mark.parametrize(
    "suffix, check, updates",
    [
        ("classification", "missing_answer", None),
        ("priority", "missing_answer", None),
        ("priority", "type_mismatch", {"type": "choice"}),
        ("priority", "confidence", {"confidence": float("nan")}),
        ("priority", "confidence", {"confidence": 10**400}),
        ("priority", "probabilities", {"probabilities": None}),
        ("priority", "probability_labels", {"probabilities": {"unexpected": 1}}),
        ("priority", "probability_value", {"probabilities": {"0": 0, "1": 0, "2": 0, "3": -1}}),
        ("priority", "probability_sum", {"probabilities": {"0": 0, "1": 0, "2": 0, "3": 0.5}}),
        ("classification", "choice", {"choice": "other"}),
        ("classification", "choice_argmax", {"choice": "likely_benign"}),
        ("priority", "score", {"score": 99}),
        ("priority", "score", {"score": -(10**400)}),
        ("priority", "score_mean", {"score": 0}),
    ],
)
def test_bad_answer_fails_only_its_row_over_mcp(
    enabled, monkeypatch, caplog, suffix, check, updates
):
    server = build_server(enabled)
    sentinel = "private-record-sentinel"
    handle = seed(server._chainsaw_ctx, [{"private": sentinel}] * 5)
    requests = []

    def handler(request):
        requests.append(request)
        data = answer(json.loads(request.content))
        name = f"row_2_{suffix}"
        if updates is None:
            del data["answers"][name]
        else:
            data["answers"][name].update(updates)
        data["answers"]["row_1_priority"].update(
            score=1, probabilities={"0": 0, "1": 1, "2": 0, "3": 0}
        )
        return httpx.Response(200, content=json.dumps(data))

    mock_api(monkeypatch, handler)
    result = payload(
        call(server, "chainsaw_jev_triage", {"handle": handle, "offset": 1, "limit": 3})
    )
    assert len(requests) == 1
    assert result["failed"] == 1 and result["returned"] == 3
    assert result["request_sent"] and result["next_offset"] == 4
    assert [a["source_row_index"] for a in result["assessments"]] == [3, 1, 2]
    failed = result["assessments"][-1]
    assert failed["classification"] is None and failed["priority"] is None
    assert failed["uncertain"] and failed["error"] == check
    assert failed["uncertain_reasons"] == ["validation_failed"]
    assert all(a["uncertain"] == bool(a["uncertain_reasons"]) for a in result["assessments"])
    assert failed["question"] == f"row_2_{suffix}"
    assert check in caplog.text and f"row_2_{suffix}" in caplog.text
    assert sentinel not in caplog.text + json.dumps(result)
    assert "test-secret" not in caplog.text + json.dumps(result)


@pytest.mark.parametrize("fault", ["top_level", "model", "answers", "unknown_answer"])
def test_invalid_response_container_rejects_batch(enabled, monkeypatch, caplog, fault):
    sentinel = "private-provider-sentinel"

    def handler(request):
        data = answer(json.loads(request.content))
        if fault == "top_level":
            data = [sentinel]
        elif fault == "model":
            data.pop("model")
        elif fault == "answers":
            data["answers"] = [sentinel]
        else:
            data["answers"][sentinel] = {"private": sentinel}
        return httpx.Response(200, json=data)

    mock_api(monkeypatch, handler)
    with pytest.raises(jev.JevError) as error:
        jev.evaluate(enabled, {"row_0": {}})
    assert error.value.check == fault
    assert fault in str(error.value)
    assert sentinel not in str(error.value) + caplog.text


def test_all_rows_can_fail_without_losing_page_provenance(enabled, monkeypatch):
    ctx = ToolContext(enabled)
    handle = seed(ctx)

    def handler(request):
        data = answer(json.loads(request.content))
        data["answers"] = {}
        return httpx.Response(200, json=data)

    mock_api(monkeypatch, handler)
    result = json.loads(JevTools(ctx).chainsaw_jev_triage(handle, min_confidence=0))
    assert result["failed"] == result["returned"] == 2
    assert result["request_sent"] and result["next_offset"] is None
    assert [a["source_row_index"] for a in result["assessments"]] == [0, 1]
    assert all(a["error"] == "missing_answer" for a in result["assessments"])
    assert all(a["classification"] is None and a["priority"] is None for a in result["assessments"])
    assert all(a["uncertain_reasons"] == ["validation_failed"] for a in result["assessments"])
    assert all(a["uncertain"] for a in result["assessments"])


@pytest.mark.parametrize(
    "score, probabilities",
    [
        (2.8, {"0": 0, "1": 0, "2": 0.2, "3": 0.8}),
        (1.5, {"0": 0.5, "1": 0, "2": 0, "3": 0.5}),
        (1.234567, {"0": 0, "1": 0.7654326, "2": 0.2345674, "3": 0}),
        # Observed live: score and probabilities are rounded to two decimals independently.
        (0.77, {"0": 0.29, "1": 0.64, "2": 0.07, "3": 0.0}),
        (2.49, {"0": 0.0, "1": 0.0, "2": 0.5, "3": 0.5}),
    ],
)
def test_score_accepts_weighted_mean_not_mode(enabled, monkeypatch, score, probabilities):
    def handler(request):
        data = answer(json.loads(request.content))
        data["answers"]["row_0_priority"].update(score=score, probabilities=probabilities)
        return httpx.Response(200, json=data)

    mock_api(monkeypatch, handler)
    result = jev.evaluate(enabled, {"row_0": {}})
    assert result["answers"]["row_0_priority"]["score"] == score


def test_request_and_response_size_limits(enabled, monkeypatch):
    mock_api(monkeypatch, lambda _: pytest.fail("Oversized request must not be sent"))
    with pytest.raises(jev.JevError, match="64000 bytes"):
        jev.evaluate(enabled, {"row_0": "x" * 64_000})


def test_oversized_batch_reports_largest_retry_prefix_over_mcp(enabled, monkeypatch):
    server = build_server(enabled)
    sentinel = "private-command-line"
    rows = [{"command": sentinel + "x" * 20_600} for _ in range(3)]
    handle = seed(server._chainsaw_ctx, [{"command": "skip"}] + rows)
    original_key = jev.api_key
    monkeypatch.setattr(jev, "api_key", lambda _: pytest.fail("Must not resolve credentials"))
    result = call(server, "chainsaw_jev_triage", {"handle": handle, "offset": 1, "limit": 3})
    assert result.is_error
    message = result.content[0].text
    assert "request_bytes=" in message
    assert "max_request_bytes=64000" in message
    assert "suggested_limit=2" in message
    assert sentinel not in message
    assert "same offset" in message

    sent = []

    def handler(request):
        sent.append(request)
        body = json.loads(request.content)
        assert body["state"]["records"] == {"row_1": rows[0], "row_2": rows[1]}
        return httpx.Response(200, json=answer(body))

    monkeypatch.setattr(jev, "api_key", original_key)
    mock_api(monkeypatch, handler)
    retry = payload(
        call(server, "chainsaw_jev_triage", {"handle": handle, "offset": 1, "limit": 2})
    )
    assert retry["returned"] == 2 and retry["next_offset"] == 3
    assert retry["request_bytes"] == len(sent[0].content) <= jev.MAX_REQUEST_BYTES


def test_single_oversized_request_reports_narrowing_advice(enabled, monkeypatch):
    mock_api(monkeypatch, lambda _: pytest.fail("Oversized request must not be sent"))
    monkeypatch.setattr(jev, "api_key", lambda _: pytest.fail("Must not resolve credentials"))
    with pytest.raises(jev.JevError) as error:
        jev.evaluate(enabled, {"row_20": {"command": "private-sentinel" + "x" * 64_000}})
    assert error.value.request_bytes > jev.MAX_REQUEST_BYTES
    assert error.value.max_request_bytes == jev.MAX_REQUEST_BYTES
    assert error.value.suggested_limit == 0
    assert "narrower fields" in str(error.value)
    assert "private-sentinel" not in str(error.value)


@pytest.mark.parametrize(
    "body, message",
    [
        (b"x" * (jev.MAX_RESPONSE_BYTES + 1), "size limit"),
        (b"not json", "invalid JSON"),
    ],
)
def test_invalid_or_oversized_response(enabled, monkeypatch, body, message):
    mock_api(monkeypatch, lambda _: httpx.Response(200, content=body))
    with pytest.raises(jev.JevError, match=message):
        jev.evaluate(enabled, {"row_0": {}})


def test_bws_resolution_uses_environment_not_arguments(enabled, monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("private-bws-token")
    token_file.chmod(0o600)
    config = replace(
        enabled,
        jev_api_key="",
        bws_token_file=str(token_file),
        jev_bws_secret_id="00000000-0000-4000-8000-000000000000",
    )

    def run(args, **kwargs):
        assert "private-bws-token" not in repr(args)
        assert kwargs["env"]["BWS_ACCESS_TOKEN"] == "private-bws-token"
        assert args[1:3] == ["secret", "get"]
        return subprocess.CompletedProcess(args, 0, '{"value":"provider-secret"}', "")

    monkeypatch.setattr(jev.subprocess, "run", run)
    assert jev.api_key(config) == "provider-secret"
    token_file.chmod(0o644)
    with pytest.raises(jev.JevError, match="private regular file"):
        jev.api_key(config)
    token_file.chmod(0o600)
    monkeypatch.setattr(
        jev.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess([], 1, "provider-secret", "private-bws-token"),
    )
    with pytest.raises(jev.JevError) as error:
        jev.api_key(config)
    assert "provider-secret" not in str(error.value)
    assert "private-bws-token" not in str(error.value)


def test_configuration_never_discloses_credentials(tmp_path):
    config = load_settings(
        {
            "CHAINSAW_HOME": str(tmp_path),
            "CHAINSAW_JEV_ENABLED": "true",
            "TYPESAFE_API_KEY": "provider-secret",
            "BWS_ACCESS_TOKEN": "private-bws-token",
        }
    )
    assert config.jev_enabled and config.describe()["jev"]["credentials_configured"]
    for value in [repr(config), json.dumps(config.describe())]:
        assert "provider-secret" not in value and "private-bws-token" not in value
    with pytest.raises(ValueError, match="must be true or false"):
        load_settings({"CHAINSAW_JEV_ENABLED": "yes"})
    with pytest.raises(ValueError, match="must be >= 1"):
        load_settings({"CHAINSAW_JEV_TIMEOUT": "0"})


def test_live_shaped_response_with_legend_usage_and_rounding(enabled, monkeypatch):
    """Shape observed against the real API on 2026-09-26: legend, usage, 2-decimal rounding."""
    ctx = ToolContext(enabled)
    handle = seed(ctx)
    sent = {}

    def handler(request):
        body = json.loads(request.content)
        sent.update(body)
        answers = {}
        for name, question in body["questions"].items():
            if question["type"] == "choice":
                answers[name] = {
                    "type": "choice",
                    "choice": "likely_benign",
                    "confidence": 0.64,
                    "probabilities": {
                        "suspicious": 0.29,
                        "likely_benign": 0.64,
                        "insufficient_context": 0.07,
                    },
                }
            else:
                answers[name] = {
                    "type": "score",
                    "score": 0.77,
                    "confidence": 0.64,
                    "legend": {str(i): text for i, text in enumerate(jev.PRIORITIES)},
                    "probabilities": {"0": 0.29, "1": 0.64, "2": 0.07, "3": 0.0},
                }
        return httpx.Response(
            200,
            json={
                "model": "jev-1.13.0",
                "answers": answers,
                "usage": {"input_tokens": 512, "output_tokens": 40, "cached": None},
            },
        )

    mock_api(monkeypatch, handler)
    out = json.loads(JevTools(ctx).chainsaw_jev_triage(handle, fields=["name", "level"]))
    assert out["request_sent"] and out["model"] == "jev-1.13.0"
    assert out["usage"] == {"input_tokens": 512, "output_tokens": 40}
    assert out["fields"] == ["name", "level"]
    assert sent["model"] == enabled.jev_model
    assert all(set(r) == {"name", "level"} for r in sent["state"]["records"].values())
    assert len(out["assessments"]) == 2
    assert all(a["priority"]["score"] == 0.77 for a in out["assessments"])
    assert "legend" not in json.dumps(out)


def test_usage_metadata_cannot_expand_the_inline_response(enabled, monkeypatch):
    server = build_server(enabled)
    handle = seed(server._chainsaw_ctx)

    def handler(request):
        data = answer(json.loads(request.content))
        data["usage"].update({"private-sentinel" + "x" * 140_000: 1, "negative_tokens": -1})
        assert len(json.dumps(data).encode()) < jev.MAX_RESPONSE_BYTES
        return httpx.Response(200, json=data)

    mock_api(monkeypatch, handler)
    result = call(server, "chainsaw_jev_triage", {"handle": handle})
    out = payload(result)
    assert len(result.content[0].text.encode()) <= DEFAULT_MAX_BYTES
    assert out["usage"] == {"input_tokens": 12, "output_tokens": 3}
    assert len(out["assessments"]) == 2
    assert "private-sentinel" not in result.content[0].text


def test_oversized_provider_model_fails_without_echoing_metadata(enabled, monkeypatch):
    def handler(request):
        data = answer(json.loads(request.content))
        data["model"] = "private-sentinel" + "x" * 140_000
        return httpx.Response(200, json=data)

    mock_api(monkeypatch, handler)
    with pytest.raises(jev.JevError, match="invalid response") as error:
        jev.evaluate(enabled, {"row_0": {}})
    assert "private-sentinel" not in str(error.value)


def test_aggregate_hunt_rows_send_every_document_value(enabled, monkeypatch):
    ctx = ToolContext(enabled)
    row = {
        "name": "Agg",
        "level": "high",
        "documents": [
            {
                "kind": "evtx",
                "path": f"/srv/{host}.evtx",
                "data": {"Event": {"System": {"Computer": host}}},
            }
            for host in ("DC01", "WS01")
        ],
    }
    handle = seed(ctx, [row])
    sent = {}

    def handler(request):
        body = json.loads(request.content)
        sent.update(body)
        return httpx.Response(200, json=answer(body))

    mock_api(monkeypatch, handler)
    out = json.loads(JevTools(ctx).chainsaw_jev_triage(handle, fields=["rule", "computer"]))
    records = list(sent["state"]["records"].values())
    assert records == [{"rule": "Agg", "computer": ["DC01", "WS01"]}]
    assert "/srv/DC01.evtx" not in json.dumps(sent)
    assert len(out["assessments"]) == 1


@pytest.mark.parametrize(
    ("secret_id", "message"),
    [("not-a-uuid", "must be a UUID"), ("", "Set TYPESAFE_API_KEY")],
)
def test_bws_secret_id_validation(enabled, secret_id, message):
    config = replace(enabled, jev_api_key="", jev_bws_secret_id=secret_id)
    with pytest.raises(jev.JevError, match=message):
        jev.api_key(config)


def test_bws_token_file_missing_or_empty(enabled, tmp_path):
    config = replace(
        enabled,
        jev_api_key="",
        jev_bws_secret_id="00000000-0000-4000-8000-000000000000",
        bws_token_file=str(tmp_path / "missing"),
    )
    with pytest.raises(jev.JevError, match="Cannot read BWS token file"):
        jev.api_key(config)
    empty = tmp_path / "empty"
    empty.write_text("\n")
    empty.chmod(0o600)
    with pytest.raises(jev.JevError, match="token is empty"):
        jev.api_key(replace(config, bws_token_file=str(empty)))


def test_bws_subprocess_is_isolated_and_failures_stay_specific(enabled, monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("private-bws-token\n")
    token_file.chmod(0o600)
    config = replace(
        enabled,
        jev_api_key="",
        jev_bws_secret_id="00000000-0000-4000-8000-000000000000",
        bws_token_file=str(token_file),
    )
    monkeypatch.setenv("TYPESAFE_API_KEY", "must-not-leak")
    monkeypatch.setenv("BWS_SERVER_URL", "https://vault.example")
    captured = {}
    outcomes = iter(
        [
            subprocess.CompletedProcess([], 0, '{"value": "  live-key  "}', ""),
            subprocess.CompletedProcess([], 0, '{"value": ""}', ""),
            subprocess.CompletedProcess([], 0, '{"value": 42}', ""),
            subprocess.CompletedProcess([], 0, "not json", ""),
            subprocess.TimeoutExpired(["bws"], 30),
            FileNotFoundError("bws"),
        ]
    )

    def run(args, **kwargs):
        captured.update(kwargs)
        outcome = next(outcomes)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(jev.subprocess, "run", run)
    assert jev.api_key(config) == "live-key"
    assert captured["stdin"] is subprocess.DEVNULL
    env = captured["env"]
    assert env["BWS_ACCESS_TOKEN"] == "private-bws-token"
    assert env["BWS_SERVER_URL"] == "https://vault.example"
    assert "TYPESAFE_API_KEY" not in env
    for message in ("empty or invalid", "empty or invalid", "check CLI", "check CLI", "check CLI"):
        with pytest.raises(jev.JevError, match=message):
            jev.api_key(config)


def test_env_key_takes_precedence_over_bws(enabled, monkeypatch):
    monkeypatch.setattr(jev.subprocess, "run", lambda *a, **k: pytest.fail("bws must not run"))
    config = replace(
        enabled,
        jev_api_key="env-key",  # gitleaks:allow (placeholder, not a credential)
        jev_bws_secret_id="00000000-0000-4000-8000-000000000000",
    )
    assert jev.api_key(config) == "env-key"

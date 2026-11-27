"""Shared connector evidence and permission handling."""

from __future__ import annotations

import pytest

from shadowscan.connectors.common import apply_matches, classify_permissions
from shadowscan.models import Finding, Kind, Surface
from shadowscan.signatures.loader import Signal, Signature
from shadowscan.signatures.matcher import Match
from shadowscan.utils.text import redact


def test_evidence_context_preserves_redaction_and_excludes_internal_match_data():
    value = "synthetic-test-value"
    match = Match(
        Signature("provider.demo", "Demo", "provider"),
        Signal(type="secret"),
        value,
        0.8,
        extra={
            "internal": value,
            "evidence_attributes": {"source_line": 12, "category": "other", "value": value},
        },
    )
    finding = Finding(Surface.CODE, "test", Kind.AGENT_CONFIG, "Demo", "demo", "repository")
    apply_matches(finding, [match])
    assert finding.evidence[0].attributes == {
        "source_line": 12,
        "category": "provider",
        "value": redact(value),
    }


@pytest.mark.parametrize("container", [set, frozenset])
def test_unordered_permissions_have_stable_order(index, container):
    finding = Finding(
        surface=Surface.SAAS,
        connector="test",
        kind=Kind.BOT_APP,
        title="Agent",
        resource="test:agent",
        resource_type="app",
    )
    scopes = container(["repo:write", "admin:org", "read:user"])

    classify_permissions(index, finding, scopes)

    assert finding.permissions == ["admin:org", "read:user", "repo:write"]


def test_ordered_permissions_preserve_provider_order(index):
    finding = Finding(
        surface=Surface.SAAS,
        connector="test",
        kind=Kind.BOT_APP,
        title="Agent",
        resource="test:agent",
        resource_type="app",
    )

    classify_permissions(index, finding, ["repo:write", "read:user", "admin:org"])

    assert finding.permissions == ["repo:write", "read:user", "admin:org"]


def test_failure_summary_names_status_or_type_without_message_text():
    from shadowscan.connectors.common import failure_summary
    from shadowscan.utils.http import HttpError

    assert failure_summary(HttpError(403, "https://api.example/v1/apps?token=secret")) == "HTTP 403"
    assert failure_summary(ValueError("Bearer secret-token echoed")) == "ValueError"
    assert "secret" not in failure_summary(RuntimeError("secret"))

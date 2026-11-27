"""Offline GitLab job commands and their source evidence."""

from pathlib import Path

import pytest

from shadowscan.connectors.code.gitlab_ci import GitLabCI

FIXTURE = Path(__file__).parents[1] / "fixtures" / "gitlab_ci"


def test_gitlab_ci_agent_evidence_on_an_archive(run_connector):
    findings, ctx = run_connector("code.filesystem", paths=[str(FIXTURE)], use_git=False)
    assert not ctx.stats.errors
    evidence = {
        (e.signature, e.location): e
        for finding in findings
        for e in finding.evidence
        if "gitlab_ci" in e.attributes
    }
    assert set(evidence) == {
        ("coding-agent.claude-code", ".gitlab-ci.yml:6"),
        ("coding-agent.openai-codex", ".gitlab-ci.yml:9"),
        ("coding-agent.claude-code", "ci/finish.sh:3"),
    }
    wrapped = evidence["coding-agent.claude-code", "ci/finish.sh:3"]
    assert wrapped.attributes["gitlab_ci"] == {
        "path": ".gitlab-ci.yml",
        "line": 11,
        "section": "after_script",
    }
    assert all("prompt" not in str(e) for e in evidence.values())


def test_yaml_command_forms_and_locations(index):
    scan = GitLabCI()
    errors = scan.observe(
        ".gitlab-ci.yaml",
        ".",
        """\
.template:
  script: &agent 'claude -p "a prompt"'
default:
  before_script: *agent
review:
  script: [npx @openai/codex, npx -y @google/gemini-cli@1.0]
  after_script: >
    npx --yes
    @anthropic-ai/claude-code
""",
    )
    assert not errors
    assert {
        (m.signature_id, m.line, m.extra["gitlab_ci"]["section"]) for _, _, m, _ in scan.matches(index)
    } == {
        ("coding-agent.claude-code", 2, "before_script"),
        ("coding-agent.openai-codex", 6, "script"),
        ("coding-agent.gemini-cli", 6, "script"),
        ("coding-agent.claude-code", 7, "after_script"),
    }


@pytest.mark.parametrize(
    "config",
    [
        "review:\n  script: [echo 'claude -p test']\nvariables: {script: 'codex exec test'}\n",
        ".unused:\n  script: npx @anthropic-ai/claude-code\n",
        "review:\n  script: |\n    cat <<'EXAMPLE'\n    codex exec test\n    EXAMPLE\n",
        "review:\n  script: |\n    echo 'example:\n    codex exec test\n    end'\n",
        "review:\n  before_script: cd somewhere-else\n  script: sh ci/finish.sh\n",
        "review:\n  script: ['cd somewhere-else', 'sh ci/finish.sh']\n",
        "review:\n  script: npx @anthropic-ai/claude-code-example\n",
    ],
)
def test_examples_and_unlinked_scripts_do_not_establish_an_agent(config, index):
    scan = GitLabCI()
    assert not scan.observe("ci/finish.sh", ".", "codex exec test")
    assert not scan.observe(".gitlab-ci.yml", ".", config)
    assert not list(scan.matches(index))


def test_ambiguous_pipeline_marks_cli_scan_incomplete(tmp_path, run_connector):
    (tmp_path / ".gitlab-ci.yml").write_text("review:\n  script: claude -p demo\n  script: echo duplicate\n")
    findings, ctx = run_connector("code.filesystem", paths=[str(tmp_path)], use_git=False)
    assert ctx.stats.incomplete
    assert not any("gitlab_ci" in e.attributes for f in findings for e in f.evidence)


def test_long_command_in_a_shell_script_only_affects_ci_coverage_when_called(tmp_path, run_connector):
    (tmp_path / "review.sh").write_text("echo " + "x" * 17_000 + "\ncodex exec demo\n")
    config = tmp_path / ".gitlab-ci.yml"
    config.write_text("review: {script: echo ok}\n")
    _, ctx = run_connector("code.filesystem", paths=[str(tmp_path)], use_git=False)
    assert not ctx.stats.incomplete
    config.write_text("review: {script: sh review.sh}\n")
    _, ctx = run_connector("code.filesystem", paths=[str(tmp_path)], use_git=False)
    assert ctx.stats.incomplete and "analysis-limit" in ctx.stats.incomplete_reasons

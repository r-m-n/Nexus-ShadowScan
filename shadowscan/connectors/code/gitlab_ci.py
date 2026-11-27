"""Static coding-agent commands in GitLab CI and literal, already-scanned shell scripts."""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.matcher import Match
from shadowscan.utils.safe_yaml import StrictBoundedConfigLoader, YAMLResourceLimitError

_CONFIGS = {".gitlab-ci.yml", ".gitlab-ci.yaml"}
_MAX_COMMAND_CHARS = 16_384
_DEFAULT_SECTIONS = {"before_script", "after_script"}
_RESERVED = {"include", "stages", "types", "variables", "workflow", "spec", "image", "services", "cache"}
_NPX_PACKAGES = {"@anthropic-ai/claude-code", "@openai/codex", "@google/gemini-cli"}
_SCRIPT_PATH = re.compile(r"(?:\./)?[\w./-]+\.(?:sh|bash)\Z")
# A line after these constructs may belong to data, a function or a different working directory.
_SHELL_CONTEXT = re.compile(
    r"<<|\$\(|`|^\s*(?:if|for|while|until|case|function|cd|pushd|popd|exit)\b|\(\s*\)"
)


class _GitLabLoader(StrictBoundedConfigLoader):
    """Accept GitLab's reference tag as opaque; it is not a literal command."""


_GitLabLoader.add_constructor("!reference", lambda loader, node: None)


@dataclass(frozen=True, slots=True)
class Invocation:
    line: int
    # Exactly one of a fixed agent command prefix or a literal relative wrapper path.
    value: str
    wrapper: bool = False


def _invocation(words: list[str], line: int) -> Invocation | None:
    if not words:
        return None
    if words[:2] in (["claude", "-p"], ["claude", "--print"], ["codex", "exec"]):
        return Invocation(line, " ".join(words[:2]))
    if words[0] == "npx":
        args = words[2:] if words[1:2] in (["--yes"], ["-y"]) else words[1:]
        package = re.fullmatch(r"(@[\w-]+/[\w-]+)(?:@[\w.^~+-]+)?", args[0]) if args else None
        if package and package[1] in _NPX_PACKAGES:
            return Invocation(line, "npx " + package[1])
    target = words[1] if len(words) > 1 and words[0] in {"sh", "bash"} else words[0]
    if (target != words[0] or target.startswith("./")) and _SCRIPT_PATH.fullmatch(target):
        path = PurePosixPath(target)
        if not target.startswith("-") and not path.is_absolute() and ".." not in path.parts:
            return Invocation(line, path.as_posix(), wrapper=True)
    return None


def _commands(
    text: str, first: int, *, physical_lines: bool = True, wrapper: bool = False
) -> Iterator[Invocation]:
    """Read simple command positions only. Never match arguments, comments or heredoc bodies."""
    pending: list[str] = []
    line = first
    for offset, raw in enumerate(text.split("\n")):
        if not pending:
            line = first + offset if physical_lines else first
        if raw.lstrip().startswith("#") and not pending:
            continue
        if raw.endswith("\\"):
            pending.append(raw[:-1])
            continue
        pending.append(raw)
        logical = "".join(pending)
        pending.clear()
        if len(logical) > _MAX_COMMAND_CHARS:
            raise YAMLResourceLimitError("GitLab CI command length exceeded")
        try:
            words = shlex.split(logical, comments=True)
        except ValueError:
            # A multiline quote may make every following physical line part of an argument.
            return
        if not words:
            continue
        if (hit := _invocation(words, line)) and (not hit.wrapper or wrapper):
            yield hit
        wrapper = False
        if _SHELL_CONTEXT.search(logical):
            return


def _fields(node: Node) -> dict[str, Node]:
    if not isinstance(node, MappingNode):
        return {}
    return {key.value: value for key, value in node.value if isinstance(key, ScalarNode)}


def _sections(root: Node) -> Iterator[tuple[str, Node, bool]]:
    top = _fields(root)
    defaults = _fields(top["default"]) if "default" in top else {}
    inherited_setup = "before_script" in top or "before_script" in defaults or "include" in top
    for job, body in top.items():
        if job in _DEFAULT_SECTIONS:
            yield job, body, True
        elif job not in _RESERVED and not job.startswith("."):
            fields = _fields(body)
            setup = inherited_setup or "before_script" in fields or "extends" in fields
            for section, commands in fields.items():
                if section in _DEFAULT_SECTIONS or (section == "script" and job != "default"):
                    yield section, commands, section != "script" or not setup


def _items(node: Node, *, wrapper: bool) -> Iterator[Invocation]:
    if node.tag == "!reference":
        return
    if isinstance(node, SequenceNode):
        for i, entry in enumerate(node.value):
            yield from _items(entry, wrapper=wrapper and i == 0)
    elif isinstance(node, ScalarNode) and node.tag == "tag:yaml.org,2002:str":
        # Folded and multiline quoted strings lose physical line boundaries in PyYAML.
        literal = node.style == "|"
        first = node.start_mark.line + (2 if literal else 1)
        yield from _commands(node.value, first, physical_lines=literal, wrapper=wrapper)


def _pipeline(text: str) -> Iterator[tuple[str, Invocation]]:
    loader = _GitLabLoader(text)
    try:
        while loader.check_data():
            root = loader.get_node()
            assert root is not None
            loader.construct_document(root)  # validate duplicate keys and apply YAML merge overrides
            for section, node, wrapper in _sections(root):
                for hit in _items(node, wrapper=wrapper):
                    yield section, hit
    finally:
        loader.dispose()


@dataclass
class GitLabCI:
    """Join pipeline calls to command prefixes observed during the ordinary confined file walk."""

    calls: list[tuple[str, str, str, Invocation]] = field(default_factory=list)
    scripts: dict[str, list[Invocation]] = field(default_factory=dict)
    limited_scripts: set[str] = field(default_factory=set)

    def observe(self, rel: str, project: str, text: str) -> list[str]:
        if rel in _CONFIGS:
            try:
                for section, hit in _pipeline(text):
                    if len(self.calls) >= 2048:
                        raise YAMLResourceLimitError("GitLab CI invocation limit exceeded")
                    self.calls.append((project, rel, section, hit))
            except (yaml.YAMLError, RecursionError) as exc:
                return [f"GitLab CI command analysis incomplete ({type(exc).__name__})"]
        elif rel.endswith((".sh", ".bash")) and any(word in text for word in ("claude", "codex", "npx")):
            # Only one source location per normalized prefix is needed to establish a wrapper.
            found: dict[str, Invocation] = {}
            try:
                for hit in _commands(text, 1):
                    if not hit.wrapper:
                        found.setdefault(hit.value, hit)
            except YAMLResourceLimitError:
                self.limited_scripts.add(rel)
            if found:
                self.scripts[rel] = list(found.values())
        return []

    def limited_wrappers(self) -> set[str]:
        """Only a wrapper referenced by this pipeline affects its coverage."""
        return self.limited_scripts.intersection(hit.value for _, _, _, hit in self.calls if hit.wrapper)

    def matches(self, index: SignatureIndex) -> Iterator[tuple[str, str, Match, str]]:
        # Only fixed prefixes are sent to the signature matcher, once each even across repeated calls.
        cache: dict[str, Match | None] = {}
        for project, config, section, call in self.calls:
            location = call.value if call.wrapper else config
            commands = self.scripts.get(location, []) if call.wrapper else [call]
            for cmd in commands:
                # A space terminates the command prefix for signatures such as 'claude -p '.
                if cmd.value not in cache:
                    hits = (
                        m for m in index.match_code(cmd.value + " ") if m.signature.category == "coding-agent"
                    )
                    cache[cmd.value] = max(hits, key=lambda m: m.weight, default=None)
                if match := cache[cmd.value]:
                    attributes = {"gitlab_ci": {"path": config, "line": call.line, "section": section}}
                    yield (
                        project,
                        location,
                        replace(
                            match, line=cmd.line, extra={**match.extra, "evidence_attributes": attributes}
                        ),
                        cmd.value,
                    )

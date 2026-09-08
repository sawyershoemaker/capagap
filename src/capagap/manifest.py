"""Build and validate dependency-free manifests for capa YAML rule collections."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capagap import __version__
from capagap.jsonio import decode_json, read_json

SCHEMA_NAME = "capagap-ruleset-manifest"
SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_RULE_BYTES = 4 * 1024 * 1024
MAX_RULE_FILES = 100_000
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
YAML_KEY = re.compile(r"^(?P<key>[^:#][^:]*):(?P<value>.*)$")


class ManifestError(ValueError):
    """Raised when a ruleset manifest or source rule is invalid."""


@dataclass(frozen=True)
class RuleManifestEntry:
    name: str
    namespace: str
    static_scope: str | None
    dynamic_scope: str | None
    library: bool
    source_digest: str
    relative_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "namespace": self.namespace,
            "static_scope": self.static_scope,
            "dynamic_scope": self.dynamic_scope,
            "library": self.library,
            "source_digest": self.source_digest,
            "path": self.relative_path,
        }


@dataclass(frozen=True)
class RuleManifest:
    path: Path
    source_name: str
    rules: dict[str, RuleManifestEntry]
    fingerprint: str
    skipped_files: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_NAME,
            "schema_version": SCHEMA_VERSION,
            "generator": {"name": "capagap", "version": __version__},
            "source": {
                "name": self.source_name,
                "rule_files": len(self.rules),
                "skipped_files": list(self.skipped_files),
            },
            "fingerprint": self.fingerprint,
            "rules": [
                entry.to_dict()
                for entry in sorted(self.rules.values(), key=lambda item: item.name)
            ],
        }


def source_digest(source: str) -> str:
    return hashlib.sha256(source.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def _fingerprint(rules: dict[str, RuleManifestEntry]) -> str:
    digest = hashlib.sha256()
    for name, entry in sorted(rules.items()):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(entry.source_digest.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _strip_plain_comment(value: str) -> str:
    for marker in (" #", "\t#"):
        if marker in value:
            value = value.split(marker, 1)[0]
    return value.rstrip()


def _yaml_scalar(raw: str, *, path: Path, field: str) -> str:
    value = raw.strip()
    if not value:
        raise ManifestError(f"{path}: rule metadata {field} cannot be empty")
    if value.startswith('"'):
        try:
            parsed = decode_json(value.encode("utf-8"))
        except (ValueError, RecursionError) as exc:
            raise ManifestError(f"{path}: invalid quoted {field}") from exc
        if not isinstance(parsed, str):
            raise ManifestError(f"{path}: rule metadata {field} must be a string")
        return parsed
    if value.startswith("'"):
        if not value.endswith("'") or len(value) < 2:
            raise ManifestError(f"{path}: invalid quoted {field}")
        return value[1:-1].replace("''", "'")
    value = _strip_plain_comment(value)
    if value in {"|", ">", "|-", ">-", "|+", ">+"}:
        raise ManifestError(f"{path}: block scalars are not supported for {field}")
    return value


def _scope(raw: str, *, path: Path, field: str) -> str | None:
    value = _yaml_scalar(raw, path=path, field=field)
    return None if value in {"unsupported", "null", "~"} else value


def _bool(raw: str, *, path: Path, field: str) -> bool:
    value = _yaml_scalar(raw, path=path, field=field).lower()
    if value in {"true", "yes"}:
        return True
    if value in {"false", "no"}:
        return False
    raise ManifestError(f"{path}: rule metadata {field} must be true or false")


def _mapping_line(content: str) -> tuple[str, str] | None:
    match = YAML_KEY.match(content)
    if not match:
        return None
    return match.group("key").strip(), match.group("value")


def _parse_rule(
    source: str, path: Path, relative_path: str
) -> RuleManifestEntry | None:
    lines = source.splitlines()
    if any(line.startswith("\t") for line in lines):
        raise ManifestError(f"{path}: tabs are not supported for YAML indentation")
    rule_index = None
    for index, line in enumerate(lines):
        if line.startswith("\t"):
            raise ManifestError(f"{path}: tabs are not supported for YAML indentation")
        if line.strip() == "rule:" and len(line) == len(line.lstrip(" ")):
            rule_index = index
            break
    if rule_index is None:
        return None

    meta_index = None
    meta_indent = None
    for index in range(rule_index + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            break
        if line.strip() == "meta:":
            meta_index = index
            meta_indent = indent
            break
    if meta_index is None or meta_indent is None:
        raise ManifestError(f"{path}: capa rule has no meta mapping")

    name: str | None = None
    namespace = ""
    static_scope: str | None = None
    dynamic_scope: str | None = None
    library = False
    field_indent: int | None = None
    scopes_indent: int | None = None

    for line in lines[meta_index + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("\t"):
            raise ManifestError(f"{path}: tabs are not supported for YAML indentation")
        indent = len(line) - len(line.lstrip(" "))
        if indent <= meta_indent:
            break
        content = line.strip()
        mapping = _mapping_line(content)
        if mapping is None:
            continue
        key, raw_value = mapping
        if field_indent is None:
            field_indent = indent

        if scopes_indent is not None and indent > scopes_indent:
            if key == "static":
                static_scope = _scope(raw_value, path=path, field="scopes.static")
            elif key == "dynamic":
                dynamic_scope = _scope(raw_value, path=path, field="scopes.dynamic")
            continue

        if indent != field_indent:
            continue
        scopes_indent = None
        if key == "name":
            name = _yaml_scalar(raw_value, path=path, field="name")
        elif key == "namespace":
            namespace = _yaml_scalar(raw_value, path=path, field="namespace")
        elif key == "lib":
            library = _bool(raw_value, path=path, field="lib")
        elif key == "scopes":
            if raw_value.strip() not in {"", "{}"}:
                raise ManifestError(f"{path}: scopes must use an indented mapping")
            scopes_indent = indent

    if name is None:
        raise ManifestError(f"{path}: capa rule metadata has no name")
    return RuleManifestEntry(
        name=name,
        namespace=namespace,
        static_scope=static_scope,
        dynamic_scope=dynamic_scope,
        library=library,
        source_digest=source_digest(source),
        relative_path=relative_path,
    )


def build_ruleset_manifest(root: str | Path) -> RuleManifest:
    """Scan a capa rule directory without loading or executing YAML tags."""

    source_root = Path(root)
    if not source_root.is_dir():
        raise ManifestError(f"ruleset root is not a directory: {source_root}")
    source_root = source_root.resolve()
    candidates = sorted(
        path
        for path in source_root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    )
    if len(candidates) > MAX_RULE_FILES:
        raise ManifestError(f"ruleset contains more than {MAX_RULE_FILES} YAML files")

    rules: dict[str, RuleManifestEntry] = {}
    skipped: list[str] = []
    for path in candidates:
        relative = path.relative_to(source_root).as_posix()
        try:
            size = path.stat().st_size
            if size > MAX_RULE_BYTES:
                raise ManifestError(
                    f"{path}: rule file exceeds {MAX_RULE_BYTES // (1024 * 1024)} MiB"
                )
            source = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise ManifestError(f"could not read rule file {path}: {exc}") from exc
        except UnicodeError as exc:
            raise ManifestError(f"rule file is not UTF-8: {path}") from exc
        entry = _parse_rule(source, path, relative)
        if entry is None:
            skipped.append(relative)
            continue
        if entry.name in rules:
            raise ManifestError(
                f"duplicate capa rule name {entry.name!r}: "
                f"{rules[entry.name].relative_path}, {relative}"
            )
        rules[entry.name] = entry

    if not rules:
        raise ManifestError(f"no capa rules found beneath: {source_root}")
    return RuleManifest(
        path=source_root,
        source_name=source_root.name,
        rules=rules,
        fingerprint=_fingerprint(rules),
        skipped_files=tuple(skipped),
    )


def _read_json(path: Path) -> Any:
    try:
        return read_json(path, MAX_MANIFEST_BYTES)
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest does not exist: {path}") from exc
    except OSError as exc:
        raise ManifestError(f"could not read manifest {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(
            f"invalid manifest JSON at line {exc.lineno}, column {exc.colno}"
        ) from exc
    except (ValueError, RecursionError) as exc:
        raise ManifestError(f"invalid manifest JSON: {exc}") from exc


def load_ruleset_manifest(path: str | Path) -> RuleManifest:
    manifest_path = Path(path)
    payload = _read_json(manifest_path)
    if not isinstance(payload, dict):
        raise ManifestError("ruleset manifest root must be an object")
    if (
        payload.get("schema") != SCHEMA_NAME
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
    ):
        raise ManifestError("unsupported ruleset manifest schema")
    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list):
        raise ManifestError("ruleset manifest rules must be an array")

    rules: dict[str, RuleManifestEntry] = {}
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise ManifestError(f"manifest rule {index} must be an object")
        name = raw.get("name")
        digest = raw.get("source_digest")
        if not isinstance(name, str) or not name:
            raise ManifestError(f"manifest rule {index} has no valid name")
        if not isinstance(digest, str) or not HEX_DIGEST.fullmatch(digest):
            raise ManifestError(f"manifest rule {name!r} has no valid source digest")
        if name in rules:
            raise ManifestError(f"duplicate rule in manifest: {name!r}")
        namespace = raw.get("namespace", "")
        static_scope = raw.get("static_scope")
        dynamic_scope = raw.get("dynamic_scope")
        library = raw.get("library", False)
        relative_path = raw.get("path", "")
        if not isinstance(namespace, str) or not isinstance(relative_path, str):
            raise ManifestError(f"manifest rule {name!r} has invalid text metadata")
        if static_scope is not None and not isinstance(static_scope, str):
            raise ManifestError(f"manifest rule {name!r} has invalid static scope")
        if dynamic_scope is not None and not isinstance(dynamic_scope, str):
            raise ManifestError(f"manifest rule {name!r} has invalid dynamic scope")
        if not isinstance(library, bool):
            raise ManifestError(f"manifest rule {name!r} has invalid library flag")
        rules[name] = RuleManifestEntry(
            name=name,
            namespace=namespace,
            static_scope=static_scope,
            dynamic_scope=dynamic_scope,
            library=library,
            source_digest=digest,
            relative_path=relative_path,
        )

    if not rules:
        raise ManifestError("ruleset manifest contains no rules")
    expected_fingerprint = _fingerprint(rules)
    if payload.get("fingerprint") != expected_fingerprint:
        raise ManifestError("ruleset manifest fingerprint does not match its entries")
    source = payload.get("source")
    source_name = (
        str(source.get("name") or "unknown") if isinstance(source, dict) else "unknown"
    )
    skipped = source.get("skipped_files", []) if isinstance(source, dict) else []
    if not isinstance(skipped, list) or any(
        not isinstance(value, str) for value in skipped
    ):
        raise ManifestError("manifest skipped_files must be an array of paths")
    return RuleManifest(
        path=manifest_path.resolve(),
        source_name=source_name,
        rules=rules,
        fingerprint=expected_fingerprint,
        skipped_files=tuple(str(value) for value in skipped if isinstance(value, str)),
    )


def write_ruleset_manifest(
    manifest: RuleManifest, output: str | Path, *, force: bool = False
) -> Path:
    destination = Path(output)
    if destination.exists() and not force:
        raise ManifestError(f"refusing to overwrite existing manifest: {destination}")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except OSError as exc:
        raise ManifestError(f"could not write manifest {destination}: {exc}") from exc
    return destination

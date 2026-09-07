"""Transparent analyst-priority heuristics for unobserved capabilities."""

from __future__ import annotations

from capagap.models import RuleRecord

NAMESPACE_WEIGHTS: tuple[tuple[str, int, str], ...] = (
    ("credential", 24, "credential-access capability"),
    ("inject", 22, "process-injection capability"),
    ("impact", 22, "impact capability"),
    ("c2", 20, "command-and-control capability"),
    ("persistence", 18, "persistence capability"),
    ("anti-analysis", 16, "anti-analysis capability"),
    ("communication", 16, "network communication capability"),
    ("execute", 15, "execution capability"),
    ("load-code", 14, "code-loading capability"),
    ("collection", 12, "collection capability"),
    ("discovery", 6, "discovery capability"),
)


def priority_label(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def score_rule(
    rule: RuleRecord, *, evasion_context: bool = False
) -> tuple[int, tuple[str, ...]]:
    """Return a bounded priority score and an auditable explanation.

    This is intentionally a triage priority, not a probability or severity score.
    """

    score = 20
    reasons: list[str] = ["statically present but absent from this dynamic result"]
    namespace = rule.namespace.lower()

    best_weight = 0
    best_reason = ""
    for token, weight, reason in NAMESPACE_WEIGHTS:
        if token in namespace and weight > best_weight:
            best_weight = weight
            best_reason = reason
    if best_weight:
        score += best_weight
        reasons.append(best_reason)

    if rule.attack_ids:
        score += min(10, 6 + len(rule.attack_ids))
        reasons.append("mapped to MITRE ATT&CK")
    if rule.mbc_ids:
        score += min(6, 3 + len(rule.mbc_ids))
        reasons.append("mapped to MBC")

    if len(rule.evidence) > 1:
        score += min(8, len(rule.evidence) * 2)
        reasons.append(f"matched at {len(rule.evidence)} static locations")

    if rule.dynamic_scope in {"call", "span of calls", "thread", "process"}:
        score += 4
        reasons.append(f"rule supports dynamic {rule.dynamic_scope} scope")

    if evasion_context and "anti-analysis" not in namespace:
        score += 8
        reasons.append("the run also observed an anti-analysis capability")

    return min(score, 100), tuple(reasons)


def suggested_action(rule: RuleRecord) -> str:
    namespace = rule.namespace.lower()
    if "anti-analysis" in namespace:
        return "Inspect the static match site and debug the decision branch; repeat in a differently fingerprinted environment."
    if "inject" in namespace:
        return "Capture child-process memory and break on the supporting allocation/write/thread APIs near the static match."
    if "persistence" in namespace:
        return "Repeat with the required privilege and longer runtime; inspect registry, service, task, and startup artifacts."
    if "communication" in namespace or "c2" in namespace:
        return "Provide controlled DNS/Internet simulation and recover endpoint/config data from the static match site."
    if "credential" in namespace:
        return "Use synthetic credentials in an isolated lab and inspect access to browser, LSASS, vault, and input APIs."
    if "collection" in namespace:
        return "Add realistic user interaction and target data, then trace the static match site and its callers."
    if "load-code" in namespace or "packer" in namespace:
        return "Dump the process after unpacking/decryption and run capa again on the recovered image."
    if "execute" in namespace:
        return "Break on the supporting execution APIs and inspect the arguments and branch conditions at the static match."
    return "Inspect the static evidence and its callers, then rerun with targeted stimuli or breakpoints."

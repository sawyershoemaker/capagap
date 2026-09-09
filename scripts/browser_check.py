"""Exercise generated offline reports and verify exported JSON with Python."""

from __future__ import annotations

import argparse
import copy
import json
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from capagap.analysis import compare_documents
from capagap.diff import compare_reports
from capagap.html_report import render_html, render_matrix_html
from capagap.io import load_document
from capagap.matrix import compare_matrix

ROOT = Path(__file__).resolve().parents[1]
HTTP = "communicate over HTTP"


def prepare_reports(folder: Path) -> dict:
    examples = ROOT / "examples/evidence"
    static = load_document(examples / "static.json")
    dynamic = load_document(examples / "dynamic.json")
    interactive = load_document(examples / "dynamic-interactive.json")
    comparisons = {
        "single": compare_documents(static, dynamic),
        "matrix": compare_matrix(
            static, [("baseline", dynamic), ("interactive", interactive)]
        ),
        "repeatability": compare_matrix(
            static,
            [("first", dynamic), ("repeat", interactive)],
            experiment_conditions=[
                ("first", "network", "off"),
                ("repeat", "network", "off"),
            ],
        ),
    }
    raw = json.loads((examples / "static.json").read_text(encoding="utf-8"))
    prototype = raw["rules"][HTTP]["matches"][0]
    matches = []
    for value in (2**53 - 1, 2**53, 2**53 + 1, 0xFFFFF80000001234, 2**64 - 1):
        match = copy.deepcopy(prototype)
        match[0]["value"] = value
        matches.append(match)
    raw["rules"][HTTP]["matches"] = matches
    large_address = folder / "large-address-input.json"
    large_address.write_text(json.dumps(raw), encoding="utf-8")
    large_static = load_document(large_address)
    comparisons["large-address-single"] = compare_documents(large_static, dynamic)
    comparisons["large-address-matrix"] = compare_matrix(
        large_static, [("baseline", dynamic), ("interactive", interactive)]
    )
    node = raw["rules"][HTTP]["matches"][0][1]
    node["node"] = {"type": "statement", "statement": {"type": "some", "count": 2}}
    node["locations"] = [
        {"type": "absolute", "value": 0x407000 + index} for index in range(9)
    ]
    evidence_path = folder / "evidence-input.json"
    evidence_path.write_text(json.dumps(raw), encoding="utf-8")
    comparisons["evidence"] = compare_documents(load_document(evidence_path), dynamic)
    hostile = copy.deepcopy(raw)
    hostile["rules"][HTTP]["meta"]["description"] = (
        '</script><img src="https://example.invalid/leak" onerror="window.auditXss=1">'
    )
    hostile_path = folder / "hostile-input.json"
    hostile_path.write_text(json.dumps(hostile), encoding="utf-8")
    comparisons["hostile"] = compare_documents(load_document(hostile_path), dynamic)
    rules = {
        f"capability {index:04d}": replace(
            static.rules[HTTP], name=f"capability {index:04d}"
        )
        for index in range(600)
    }
    comparisons["large"] = compare_matrix(
        replace(static, rules=rules),
        [
            (
                f"run-{index}",
                replace(
                    dynamic,
                    rules={
                        name: rule
                        for number, (name, rule) in enumerate(rules.items())
                        if (number + index) % 4
                    },
                ),
            )
            for index in range(4)
        ],
    )
    for name, comparison in comparisons.items():
        renderer = render_matrix_html if hasattr(comparison, "runs") else render_html
        (folder / f"{name}.html").write_text(renderer(comparison), encoding="utf-8")
    return comparisons


@contextmanager
def serve(folder: Path):
    class Handler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), partial(Handler, directory=str(folder))
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def run(folder: Path, *, channel: str | None = None, axe: Path | None = None) -> dict:
    from playwright.sync_api import sync_playwright

    comparisons = prepare_reports(folder)
    results = {"checks": [], "failures": [], "accessibility": []}

    def check(name, passed, detail=None):
        results["checks" if passed else "failures"].append(
            {"name": name, "detail": detail}
        )

    with serve(folder) as base, sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            **({"channel": channel} if channel else {})
        )
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        page = context.new_page()
        errors, external = [], []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on(
            "request",
            lambda request: (
                external.append(request.url)
                if not request.url.startswith((base, "blob:", "data:"))
                else None
            ),
        )
        for name in (
            "single",
            "matrix",
            "large-address-single",
            "large-address-matrix",
            "repeatability",
        ):
            page.goto(base + name + ".html")
            with page.expect_download() as event:
                page.locator("[data-export]").click()
            download = event.value
            destination = folder / f"{name}-export.json"
            download.save_as(destination)
            # Decode independently: JS-parsed comparisons would hide rounded ints.
            exported = json.loads(destination.read_text(encoding="utf-8"))
            expected = comparisons[name].to_dict()
            check(f"{name}: exact JSON round trip", exported == expected)
            try:
                check(
                    f"{name}: exported evidence fingerprints",
                    not compare_reports(expected, exported)["changed"],
                )
            except ValueError as error:
                check(f"{name}: exported evidence fingerprints", False, str(error))
            expected_name = (
                "capagap-matrix.json"
                if hasattr(comparisons[name], "runs")
                else "capagap-comparison.json"
            )
            check(
                f"{name}: download filename",
                download.suggested_filename == expected_name,
            )

        for width in (1440, 390):
            page.set_viewport_size({"width": width, "height": 900})
            page.goto(base + "repeatability.html")
            disclosure = page.locator("#run-repeatability")
            disclosure.locator("summary").focus()
            page.keyboard.press("Enter")
            check(
                f"{width}px: repeatability keyboard disclosure",
                disclosure.get_attribute("open") is not None,
            )
            check(
                f"{width}px: repeatability counts",
                "2 intermittent" in disclosure.inner_text()
                and disclosure.locator("tbody tr").count() == 4,
            )
            check(
                f"{width}px: repeatability fits",
                page.evaluate("document.documentElement.scrollWidth === innerWidth"),
            )
            disclosure.scroll_into_view_if_needed()
            page.screenshot(path=folder / f"repeatability-{width}.png")
        page.set_viewport_size({"width": 1440, "height": 1000})
        page.goto(base + "matrix.html")
        check(
            "matrix starts with comparable findings",
            page.locator("[data-record]:visible").count() == 4,
        )
        page.screenshot(path=folder / "desktop.png")
        page.locator("input[data-search]").fill("HttpSendRequestA")
        check("evidence search", page.locator("[data-record]:visible").count() == 1)
        page.locator("[data-state-filter]").select_option("never-observed")
        check("combined empty filters", page.locator("[data-empty]").is_visible())
        page.locator("[data-reset]").click()
        page.locator("#finding-0-toggle").focus()
        page.keyboard.press("ArrowDown")
        page.keyboard.press("ArrowRight")
        check("keyboard expansion", page.locator("#finding-1-detail").is_visible())
        page.keyboard.press("Escape")
        check(
            "Escape restores row focus",
            page.locator("#finding-1-toggle").evaluate(
                "el => el === document.activeElement"
            ),
        )
        page.locator("#finding-0-toggle").focus()
        page.keyboard.press("ArrowRight")
        page.evaluate(
            "Object.defineProperty(navigator, 'clipboard', {configurable:true, value:{writeText:async () => {throw Error('Denied');}}})"
        )
        copy_button = page.locator('#finding-0-detail [data-copy="0x4000"]')
        copy_button.click()
        check(
            "copy-denied fallback",
            page.locator("dialog[open] textarea").input_value() == "0x4000",
        )
        page.keyboard.press("Escape")
        check(
            "copy fallback restores focus",
            copy_button.evaluate("el => el === document.activeElement"),
        )
        if axe:
            page.add_script_tag(path=str(axe.resolve()))
            for group in ("comparable", "runtime", "excluded"):
                page.locator(f'[data-group-button="{group}"]').click()
                page.evaluate(
                    "() => Promise.all(document.getAnimations().map(a => a.finished.catch(() => {})))"
                )
                violations = page.evaluate(
                    "async () => (await axe.run(document)).violations.map(v => ({id:v.id, targets:v.nodes.map(n=>n.target)}))"
                )
                results["accessibility"].append(
                    {"group": group, "violations": violations}
                )
                check(f"{group}: automated accessibility", not violations)
        page.evaluate("window.dispatchEvent(new Event('beforeprint'))")
        page.emulate_media(media="print")
        check(
            "print retains filtered groups",
            page.locator("[data-record]:visible").count() == 7
            and page.locator(".details-row:visible").count() == 7,
        )
        page.emulate_media(media="screen", reduced_motion="reduce")
        page.evaluate("window.dispatchEvent(new Event('afterprint'))")
        check(
            "reduced motion",
            page.locator(".row-toggle .icon").first.evaluate(
                "el => getComputedStyle(el).transitionDuration === '0s'"
            ),
        )

        for width in (1440, 768, 390, 320):
            page.set_viewport_size({"width": width, "height": 900})
            page.goto(base + "matrix.html")
            check(
                f"{width}px: page fits",
                page.evaluate("document.documentElement.scrollWidth === innerWidth"),
            )
            if width == 390:
                page.screenshot(path=folder / "mobile.png")
                page.locator("input[data-search]").fill(HTTP)
                page.locator("[data-record]:visible .row-toggle").click()
                page.locator(
                    ".details-row:visible .match-evidence > summary"
                ).first.click()
                check(
                    "expanded mobile evidence fits",
                    page.evaluate(
                        "document.documentElement.scrollWidth === innerWidth"
                    ),
                )
                page.screenshot(path=folder / "mobile-evidence.png", full_page=True)
        text_scale = page.evaluate("""() => {
          const sizes = [...document.querySelectorAll('body *')].filter(e => !['SCRIPT','STYLE','SVG','PATH'].includes(e.tagName)).map(e => [e,parseFloat(getComputedStyle(e).fontSize)]);
          const before = getComputedStyle(document.querySelector('.row-toggle')).fontSize;
          sizes.forEach(([e,n]) => e.style.setProperty('font-size', 2*n+'px', 'important'));
          return {before, after:getComputedStyle(document.querySelector('.row-toggle')).fontSize, width:document.documentElement.scrollWidth, viewport:innerWidth};
        }""")
        check(
            "200-percent text stress fits",
            text_scale["width"] == text_scale["viewport"],
            text_scale,
        )
        check(
            "enlarged address columns stay separated",
            page.locator(".details-row:visible .evidence-table tbody tr").evaluate_all(
                """rows => rows.every(row => {
                  const code = row.cells[0].querySelector('code');
                  if (!code || row.cells.length < 3) return true;
                  const range = document.createRange();
                  range.selectNodeContents(code);
                  const next = row.cells[1].getBoundingClientRect().left;
                  return [...range.getClientRects()].every(rect => rect.right <= next - 8);
                })"""
            ),
        )
        page.screenshot(path=folder / "mobile-double-text.png", full_page=True)
        page.goto(base + "evidence.html")
        page.locator("input[data-search]").fill(HTTP)
        page.locator("[data-record]:visible .row-toggle").click()
        tree = page.locator(".details-row:visible .match-evidence").first
        tree.locator("summary").first.click()
        text = tree.inner_text()
        check("threshold statement includes its count", "some: at least 2" in text)
        check(
            "hidden ninth location is disclosed",
            "0x407008" not in text and "omits detail" in text,
        )
        page.goto(base + "hostile.html")
        check(
            "hostile description stays inert",
            page.evaluate("!window.auditXss && !document.querySelector('img')"),
        )
        page.set_viewport_size({"width": 1440, "height": 1000})
        started = time.perf_counter()
        page.goto(base + "large.html")
        results["large_load_ms"] = round((time.perf_counter() - started) * 1000)
        check(
            "large report retains 600 findings",
            page.locator("[data-record]:visible").count() == 600,
        )
        started = time.perf_counter()
        page.locator("input[data-search]").fill("capability 0599")
        results["large_filter_ms"] = round((time.perf_counter() - started) * 1000)
        check("large report filter", page.locator("[data-record]:visible").count() == 1)
        no_js = browser.new_context(
            java_script_enabled=False, viewport={"width": 390, "height": 844}
        )
        fallback = no_js.new_page()
        fallback.goto(base + "matrix.html")
        check(
            "no-JS retains all findings and evidence",
            fallback.locator("[data-record]:visible").count() == 7
            and fallback.locator(".details-row:visible").count() == 7,
        )
        check(
            "no-JS mobile fits",
            fallback.evaluate("document.documentElement.scrollWidth === innerWidth"),
        )
        no_js.close()
        check("no JavaScript errors", not errors, errors)
        check("no external report requests", not external, external)
        browser.close()
    (folder / "browser-results.json").write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8"
    )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--outdir", type=Path, help="New or empty directory for reports and screenshots"
    )
    parser.add_argument(
        "--channel", help="Use an installed browser channel, such as chrome"
    )
    parser.add_argument(
        "--axe", type=Path, help="Optional local axe.min.js for accessibility checks"
    )
    args = parser.parse_args()
    if args.outdir:
        if args.outdir.exists() and (
            not args.outdir.is_dir() or any(args.outdir.iterdir())
        ):
            parser.error("--outdir must be new or empty")
        args.outdir.mkdir(parents=True, exist_ok=True)
        results = run(args.outdir.resolve(), channel=args.channel, axe=args.axe)
    else:
        with tempfile.TemporaryDirectory(prefix="capagap-browser-") as directory:
            results = run(Path(directory), channel=args.channel, axe=args.axe)
    print(json.dumps(results, indent=2))
    return 1 if results["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

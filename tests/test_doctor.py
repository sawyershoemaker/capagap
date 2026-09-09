from __future__ import annotations

import json
import os
from types import SimpleNamespace
from unittest.mock import patch

from capagap import __version__
from capagap.doctor import inspect_installation
from tests.test_workflows import WorkflowTestCase


class DoctorTests(WorkflowTestCase):
    def setUp(self):
        super().setUp()
        self.scripts = self.root / "Scripts"
        self.scripts.mkdir()
        self.launcher = self.scripts / ("capagap.exe" if os.name == "nt" else "capagap")
        self.launcher.write_bytes(b"not executable test data")
        self.user_site = self.root / "user-site"
        self.distribution = SimpleNamespace(
            version=__version__,
            entry_points=[
                SimpleNamespace(
                    name="capagap", group="console_scripts", value="capagap.cli:main"
                )
            ],
            locate_file=lambda _: self.root / "site",
        )
        for target, kwargs in (
            (
                "capagap.doctor.metadata.distribution",
                {"return_value": self.distribution},
            ),
            ("capagap.doctor.sysconfig.get_path", {"return_value": str(self.scripts)}),
            (
                "capagap.doctor.site.getusersitepackages",
                {"return_value": str(self.user_site)},
            ),
            (
                "capagap.doctor.shutil.which",
                {
                    "side_effect": lambda name: (
                        str(self.launcher) if name == "capagap" else None
                    )
                },
            ),
        ):
            patcher = patch(target, **kwargs)
            self.addCleanup(patcher.stop)
            patcher.start()

    def test_healthy_install_does_not_require_capa(self):
        result = inspect_installation()
        self.assertTrue(result["passed"])
        self.assertIsNone(result["optional_tools"][0]["resolved"])
        self.assertEqual(result["command"]["verification"], "path-and-metadata-only")

    def test_missing_path_gives_scripts_directory(self):
        with patch("capagap.doctor.shutil.which", return_value=None):
            result = inspect_installation()
        codes = {item["code"] for item in result["diagnostics"]}
        self.assertIn("command-not-on-path", codes)
        self.assertNotIn("launcher-missing", codes)
        self.assertEqual(
            result["command"]["scripts_directory"], str(self.scripts.resolve())
        )

    def test_foreign_launcher_is_not_assumed_to_match(self):
        with patch(
            "capagap.doctor.shutil.which",
            return_value=str(self.root / "elsewhere/capagap"),
        ):
            result = inspect_installation()
        self.assertIn("different-launcher", {d["code"] for d in result["diagnostics"]})

    def test_missing_launcher_is_reported(self):
        self.launcher.unlink()
        result = inspect_installation()
        self.assertIn("launcher-missing", {d["code"] for d in result["diagnostics"]})

    def test_user_install_selects_user_scripts_scheme(self):
        self.distribution.locate_file = lambda _: self.user_site
        user_scripts = self.root / "user-scripts"
        with patch(
            "capagap.doctor.sysconfig.get_path",
            side_effect=lambda name, **kwargs: str(
                user_scripts if "scheme" in kwargs else self.scripts
            ),
        ):
            result = inspect_installation()
        self.assertEqual(
            result["command"]["scripts_directory"], str(user_scripts.resolve())
        )

    def test_version_and_entry_point_mismatches(self):
        self.distribution.version = "0.0.0"
        self.distribution.entry_points = []
        codes = {d["code"] for d in inspect_installation()["diagnostics"]}
        self.assertTrue({"version-mismatch", "entry-point-missing"} <= codes)

    def test_missing_metadata_is_a_diagnostic(self):
        from importlib.metadata import PackageNotFoundError

        with patch(
            "capagap.doctor.metadata.distribution",
            side_effect=PackageNotFoundError("capagap"),
        ):
            result = inspect_installation()
        self.assertIn(
            "metadata-unavailable", {d["code"] for d in result["diagnostics"]}
        )

    def test_no_execution_or_environment_mutation(self):
        before = dict(os.environ)
        with patch(
            "subprocess.run", side_effect=AssertionError("must not execute tools")
        ):
            inspect_installation()
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(self.launcher.read_bytes(), b"not executable test data")

    def test_broken_metadata_does_not_crash_the_diagnostic(self):
        self.distribution.entry_points = None
        result = inspect_installation()
        self.assertIn("metadata-unreadable", {d["code"] for d in result["diagnostics"]})

    def test_cli_formats_and_strict_exit(self):
        for fmt in ("text", "markdown", "json"):
            code, output, error = self.cli("doctor", "--format", fmt, "--strict")
            self.assertEqual(code, 0, error)
            self.assertIn("capagap", output.lower())
        with patch("capagap.doctor.shutil.which", return_value=None):
            self.assertEqual(self.cli("doctor")[0], 0)
            code, output, error = self.cli("doctor", "--strict", "--format", "json")
        self.assertEqual(code, 4, error)
        self.assertFalse(json.loads(output)["passed"])

    def test_explicit_report_output(self):
        output = self.root / "doctor.json"
        self.assertEqual(
            self.cli("doctor", "--format", "json", "--output", output)[0], 0
        )
        self.assertEqual(json.loads(output.read_text())["schema"], "capagap-doctor")

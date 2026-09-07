from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from capagap import __version__
from capagap.cli import main as cli_main
from scripts import release_check


class ReleaseTests(unittest.TestCase):
    def test_source_version_matches_runtime(self):
        self.assertEqual(release_check.source_version(), __version__)

    def test_cli_version(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            cli_main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), f"capagap {__version__}")

    def test_matching_tag(self):
        release_check.check_tag(f"v{__version__}", __version__)

    def test_wrong_or_missing_tag_prefix(self):
        for tag in ("v999.0.0", __version__, "", "v0.1.0; echo unexpected"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release_check.check_tag(tag, __version__)

    def test_empty_or_new_output_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_check.check_output_directory(root)
            release_check.check_output_directory(root / "new")

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = root / "prior.whl"
            prior.write_bytes(b"keep this file")
            for path in (root, prior):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    release_check.check_output_directory(path)
            self.assertEqual(prior.read_bytes(), b"keep this file")

    def test_distribution_names_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / f"capagap-{__version__}-py3-none-any.whl"
            sdist = root / f"capagap-{__version__}.tar.gz"
            with self.assertRaises(ValueError):
                release_check.distributions(root, __version__)
            wheel.touch()
            sdist.touch()
            self.assertEqual(
                release_check.distributions(root, __version__), (wheel, sdist)
            )
            (root / "capagap-999.0.0.tar.gz").touch()
            with self.assertRaises(ValueError):
                release_check.distributions(root, __version__)

    def test_wrong_tag_stops_before_commands_run(self):
        with patch.object(release_check, "_run") as run:
            with patch("sys.stderr", new=io.StringIO()):
                result = release_check.main(["--tag", "v999.0.0"])
        self.assertEqual(result, 1)
        run.assert_not_called()

    def test_nonempty_output_stops_before_commands_run(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "prior.whl").touch()
            with patch.object(release_check, "_run") as run:
                with patch("sys.stderr", new=io.StringIO()):
                    result = release_check.main(["--outdir", directory])
            self.assertEqual(result, 1)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Tests of the web UI's ZK form handling (no proofs: the CLIs are not run).

Run from web-ui/: python -m unittest test_app
"""

import os
import re
import subprocess
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest import mock

import app as web


def selected(html: str, name: str) -> str | None:
    """The value of the selected option of the select named `name`."""
    select = re.search(rf'<select name="{name}".*?</select>', html, re.S).group(0)
    m = re.search(r'<option value="([^"]+)"[^>]*\bselected\b', select)
    return m.group(1) if m else None


class AnonymizeForm(unittest.TestCase):
    def setUp(self):
        self.client = web.app.test_client()
        self.keys = tempfile.TemporaryDirectory()
        root = Path(self.keys.name)
        modes = {k: dict(m, keys=root / m["keys"].name) for k, m in web.ZK_MODES.items()}
        for m in modes.values():
            m["keys"].mkdir()
            (m["keys"] / "statement.pk").write_bytes(b"")
        self.modes = modes
        for p in (mock.patch.object(web, "ZK_MODES", modes), mock.patch.object(web, "ensure_zk_pki")):
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.keys.cleanup()

    def post(self, **form):
        return self.client.post("/zk/anonymize", data=form, content_type="multipart/form-data").get_data(as_text=True)

    def assert_choices_kept(self, html):
        self.assertEqual(selected(html, "mode"), "hidden-all")
        self.assertEqual(selected(html, "time_window"), "1h")
        self.assertRegex(html, r'name="scrub_metadata"\s+checked')

    def test_invalid_upload_keeps_the_privacy_choices(self):
        html = self.post(image=(BytesIO(b"x"), "notes.txt"), mode="hidden-all", time_window="1h", scrub_metadata="on")
        self.assertIn("signed PNG or JPEG", html)
        self.assert_choices_kept(html)

    def test_missing_keys_keep_the_privacy_choices(self):
        (self.modes["hidden-all"]["keys"] / "statement.pk").unlink()
        html = self.post(image=(BytesIO(b"x"), "a.png"), mode="hidden-all", time_window="1h", scrub_metadata="on")
        self.assertIn("No keys for this mode", html)
        self.assertIn(str(self.modes["hidden-all"]["keys"]), html)  # the setup hint names the configured path
        self.assert_choices_kept(html)

    def test_a_missing_mode_is_refused_not_disclosed(self):
        with mock.patch.object(web.threading, "Thread") as thread:
            html = self.post(image=(BytesIO(b"x"), "a.png"), time_window="1h")
        self.assertIn("Choose an available mode", html)
        thread.assert_not_called()

    def test_defaults_on_a_fresh_form(self):
        html = self.client.get("/zk/anonymize").get_data(as_text=True)
        self.assertEqual(selected(html, "mode"), "disclosed")
        self.assertEqual(selected(html, "time_window"), "1d")
        self.assertNotRegex(html, r'name="scrub_metadata"\s+checked')

    def test_the_title_holds_no_script(self):
        html = self.client.get("/zk/anonymize").get_data(as_text=True)
        title = re.search(r"<title>(.*?)</title>", html, re.S).group(1)
        self.assertNotIn("script", title)
        self.assertEqual(html.count("<script>"), html.count("</script>"))


class KeysRoot(unittest.TestCase):
    def test_a_relative_root_is_made_absolute(self):
        with tempfile.TemporaryDirectory() as cwd:
            out = subprocess.run(
                [sys.executable, "-c", "import app; print(app.ZK_KEYS_ROOT); print(app.ZK_MODES['disclosed']['keys'])"],
                cwd=cwd, env={**os.environ, "C2PA_ZK_KEYS_ROOT": "keys", "PYTHONPATH": str(Path(__file__).parent)},
                capture_output=True, text=True, check=True,
            ).stdout.split()
        expected = Path(cwd).resolve() / "keys"
        self.assertEqual(Path(out[0]), expected)
        self.assertEqual(Path(out[1]), expected / "gnark-keys")


if __name__ == "__main__":
    unittest.main()

"""Progress is measured from stages/bytes, never elapsed time."""
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import service_events as events


class ProgressTests(unittest.TestCase):
    def test_stages_and_partial_bytes_are_monotonic_and_only_verified_is_100(self):
        output = io.StringIO()
        with patch.object(events, "_stream", output):
            progress = events.StageProgress(("check", "write", "verify"))
            progress.start("check")
            progress.start("write")
            progress.update(5, 10)
            progress.update(2, 10)  # repeated reports cannot move the bar back
            progress.update(10, 10)
            progress.start("verify")
            progress.complete("Verified")
        values = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([v["overall_percent"] for v in values], [0, 33, 50, 50, 66, 66, 100])
        self.assertEqual([v["steps_done"] for v in values], [0, 1, 1, 1, 2, 2, 3])
        self.assertTrue(all(v["steps_total"] == 3 for v in values))

    def test_repeated_checkpoint_keeps_byte_progress(self):
        output = io.StringIO()
        with patch.object(events, "_stream", output):
            progress = events.StageProgress(("write", "verify"))
            progress.start("write")
            progress.update(8, 10)
            progress.start("write")
        values = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(values[-1]["overall_percent"], 40)

    def test_invalid_stage_order_and_byte_total_are_rejected(self):
        progress = events.StageProgress(("a", "b"))
        progress.start("b")
        with self.assertRaises(ValueError): progress.start("a")
        with self.assertRaises(ValueError): progress.update(1, 0)
        with self.assertRaises(ValueError): events.StageProgress(("a", "a"))

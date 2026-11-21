import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from avc_batch import event_batches, write_batch

SAMPLE = Path(__file__).resolve().parents[1] / "exemplo.log"


class BatchTests(unittest.TestCase):
    def test_partial_batch_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "review.zip"
            failures = write_batch([SAMPLE, root / "missing.log"], output, "Portal")
            self.assertEqual(failures, 1)
            with ZipFile(output) as archive:
                manifest = json.loads(archive.read("provenance.json"))
                good, bad = manifest["inputs"]
                self.assertEqual(good["sha256"], hashlib.sha256(SAMPLE.read_bytes()).hexdigest())
                self.assertEqual(good["parsed"], 3)
                self.assertEqual(bad["status"], "error")
                events = json.loads(archive.read(good["events"][0]))
                self.assertEqual(len(events), 2)
                self.assertEqual(events[0]["ativo"], "Portal")
            original = output.read_bytes()
            with self.assertRaises(FileExistsError):
                write_batch([SAMPLE], output)
            self.assertEqual(output.read_bytes(), original)

    def test_splits_on_count_and_serialized_byte_size(self):
        small = [{"mensagem": "abc"}] * 1001
        self.assertEqual([len(json.loads(batch)) for batch in event_batches(small)], [1000, 1])
        large = [{"mensagem": "á" * 300000}] * 3
        self.assertEqual(len(list(event_batches(large))), 3)


if __name__ == "__main__":
    unittest.main()

"""Regression checks runnable with unittest as well as pytest."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from eraseproof import attackgate, independent
from eraseproof.engine import validate_references
from eraseproof.models import EraseProofError


class ZeroOutputGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.image = self.root / 'source.img'
        self.image.write_bytes(bytes(8192))
        self.output = self.root / 'attack'
        self.output.mkdir()

    def check(self, payload, *, status='completed', refs=None, recovered_count=1,
              zero_readback=True, metadata_status='filesystem-unrecognized-or-error',
              feature_status='completed', mutate_source=False):
        recovered = self.output / 'recovered.dovecot'
        recovered.write_bytes(payload)
        feature = self.output / 'feature.txt'
        feature.write_bytes(b'# bulk_extractor metadata header\n')
        report = {'tools': [
            {'tool': 'PhotoRec', 'status': status, 'files': [{'path': str(recovered)}]},
            {'tool': 'Sleuth Kit', 'status': metadata_status},
            {'tool': 'bulk_extractor', 'status': feature_status, 'files': [{'path': str(feature)}]},
        ], 'recovered_files': recovered_count, 'complete': False}
        expected = hashlib.sha256(self.image.read_bytes()).hexdigest()
        def attack(*args, **kwargs):
            if mutate_source:
                with self.image.open('r+b') as source:
                    source.write(b'x')
            return report
        with self.image.open('rb') as stream, patch.object(independent, 'attack', side_effect=attack):
            return attackgate.check(self.image, self.output, refs, stream=stream,
                length=8192, expected_sha256=expected, zero_readback=zero_readback)

    def test_metadata_failure_requires_complete_zero_readback(self):
        self.assertFalse(self.check(bytes(81920), zero_readback=False)['passed'])

    def test_other_metadata_failures_are_not_superseded(self):
        for status in ('timeout', 'failed', 'missing', 'output-limit'):
            with self.subTest(status=status):
                self.assertFalse(self.check(bytes(81920), metadata_status=status)['passed'])

    def test_incomplete_feature_scan_still_blocks(self):
        for status in ('timeout', 'failed', 'missing', 'output-limit', 'incomplete'):
            with self.subTest(status=status):
                self.assertFalse(self.check(bytes(81920), feature_status=status)['passed'])

    def test_source_change_during_independent_scan_blocks(self):
        with self.assertRaisesRegex(EraseProofError, 'Source changed during'):
            self.check(bytes(81920), mutate_source=True)

    def test_zero_outputs_are_preserved_without_becoming_surviving_content(self):
        result = self.check(bytes(81920))
        self.assertTrue(result['passed'])
        self.assertEqual(result['recovered_files'], 1)
        self.assertEqual(result['zero_only_recovered_files'], 1)
        self.assertEqual(result['nonzero_recovered_files'], 0)
        report = json.loads(Path(result['report']).read_text())
        self.assertEqual(report['tools'][0]['files'][0]['nonzero_bytes'], 0)
        self.assertEqual((self.output/'recovered.dovecot').stat().st_size, 81920)
        self.assertTrue(result['source_unchanged'])

    def test_one_nonzero_recovered_byte_still_blocks_certification(self):
        result = self.check(bytes(81919) + b'x')
        self.assertFalse(result['passed'])
        self.assertEqual(result['nonzero_recovered_files'], 1)

    def test_an_incomplete_recovered_file_inventory_still_blocks(self):
        self.assertFalse(self.check(bytes(81920), recovered_count=2)['passed'])

    def test_successful_gate_can_be_signed_and_verified(self):
        from eraseproof.evidence import EvidenceStore, verify_record
        gate = self.check(bytes(81920))
        store = EvidenceStore(self.root / 'evidence')
        record = store.certify({'schema': 'eraseproof.native-evidence.v1',
            'id': 'zero-artifact-regression', 'verification': {
            'passed': gate['passed'], 'rrs': 0, 'independent_attack': gate}})
        self.assertTrue(record['payload']['certificate_issued'])
        self.assertTrue(verify_record(record))
        self.assertTrue(store.check())

    def test_incomplete_scanner_still_blocks_with_zero_outputs(self):
        for status in ('timeout', 'failed', 'output-limit', 'low-disk-space'):
            with self.subTest(status=status):
                self.assertFalse(self.check(bytes(81920), status=status)['passed'])

    def test_zero_output_matching_a_reference_still_blocks(self):
        data = bytes(81920)
        result = self.check(data, refs={'file_hashes': [hashlib.sha256(data).hexdigest()]})
        self.assertFalse(result['passed'])
        self.assertEqual(result['target_reference_matches'], 1)

    def test_nonzero_count_includes_the_final_chunk(self):
        path = self.root / 'chunks.bin'
        path.write_bytes(bytes(4*1024*1024) + b'\0x\0y')
        result = attackgate.scan_file(path, validate_references(None))
        self.assertEqual(result['nonzero_bytes'], 2)


class RealScannerZeroOutputTests(unittest.TestCase):
    def test_real_scanners_complete_against_an_all_zero_image(self):
        helper = os.environ.get('ERASEPROOF_TEST_BULK_EXTRACTOR') or independent.bulk_tool()
        if not helper or any(not shutil.which(tool) for tool in ('photorec', 'fls', 'icat', 'prlimit')):
            self.skipTest('Independent forensic tools are not built/installed')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / 'zero.img'
            image.write_bytes(bytes(8*1024*1024))
            with image.open('rb') as stream, patch.object(independent, 'bulk_tool', return_value=helper):
                result = attackgate.check(image, root/'attack', None, stream=stream,
                    length=image.stat().st_size, expected_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                    zero_readback=True)
            self.assertTrue(result['passed'], result)
            self.assertEqual(result['nonzero_recovered_files'], 0)
            self.assertEqual(result['zero_only_recovered_files'], result['recovered_files'])
            self.assertEqual(result['required_tools']['PhotoRec'], 'completed')
            self.assertEqual(result['required_tools']['bulk_extractor'], 'completed')


if __name__ == '__main__':
    unittest.main()

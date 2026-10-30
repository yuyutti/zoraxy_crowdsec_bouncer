"""Release identity guards use only Python, including failure cases."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from verify_release import source_version

class ReleaseIdentityTests(unittest.TestCase):
    def setUp(self):
        self.source = Path.cwd()
        self.temp = tempfile.TemporaryDirectory()
        target = Path(self.temp.name)
        (target / 'mod/info').mkdir(parents=True)
        for name in ('mod/info/info.go', '.introspect', '.releaseurl'):
            (target / name).write_bytes((self.source / name).read_bytes())
        os.chdir(target)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(os.chdir, self.source)

    def test_exact_fork_metadata(self):
        self.assertEqual(source_version(), 'v1.2.4-2')

    def test_latest_endpoint_rejected_for_evaluation(self):
        Path('.releaseurl').write_text('https://github.com/yuyutti/zoraxy_crowdsec_bouncer/releases/latest/download\n', encoding='utf-8')
        with self.assertRaises(AssertionError):
            source_version()

    def test_other_repository_metadata_rejected(self):
        path = Path('.introspect')
        data = json.loads(path.read_text())
        data['url'] = 'https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer'
        path.write_text(json.dumps(data), encoding='utf-8')
        with self.assertRaises(AssertionError):
            source_version()

    def test_different_binary_version_rejected(self):
        path = Path('.introspect')
        data = json.loads(path.read_text())
        data['version'] = 'v1.2.5'
        path.write_text(json.dumps(data), encoding='utf-8')
        with self.assertRaises(AssertionError):
            source_version()

if __name__ == '__main__':
    unittest.main()

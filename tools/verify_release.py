"""Verify source/SDK/release identity without installing Go on the caller's PC."""
import json
import os
from pathlib import Path
import re
import sys

REPOSITORY = 'yuyutti/zoraxy_crowdsec_bouncer'

def source_version():
    source = Path('mod/info/info.go').read_text(encoding='utf-8-sig')
    version = re.search(r'VERSION_STRING\s*=\s*"(v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9]+)?)"', source).group(1)
    metadata = json.loads(Path('.introspect').read_text(encoding='utf-8-sig'))
    assert metadata['version'] == version, 'Full introspection version mismatch'
    assert metadata['id'] == 'com.yuyutti.zoraxycrowdsecbouncer', 'Fork Plugin ID mismatch'
    base = version[1:].split('-')[0].split('.')
    assert [metadata['version_major'], metadata['version_minor'], metadata['version_patch']] == list(map(int, base)), 'SDK numeric version mismatch'
    assert metadata['url'] == 'https://github.com/' + REPOSITORY, 'Fork URL mismatch'
    release_url = Path('.releaseurl').read_text(encoding='utf-8-sig').strip()
    assert release_url == 'https://github.com/' + REPOSITORY + '/releases/download/' + version, 'Evaluation .releaseurl must use the exact tag'
    return version

if __name__ == '__main__':
    version = source_version()
    if '--event' in sys.argv:
        assert os.environ['GITHUB_REPOSITORY'] == REPOSITORY, 'Release repository mismatch'
        event = os.environ['GITHUB_EVENT_NAME']
        if event == 'push':
            assert os.environ['GITHUB_REF'] == 'refs/tags/' + version, 'Tag/source version mismatch'
            prerelease = True
        else:
            assert event == 'workflow_dispatch', 'Unsupported publication event'
            assert os.environ['REQUESTED_VERSION'] == version, 'Requested/source version mismatch'
            prerelease = os.environ['REQUESTED_PRERELEASE'].lower() == 'true'
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write('version=' + version + '\nprerelease=' + str(prerelease).lower() + '\n')
    print('Verified fork source version: ' + version)

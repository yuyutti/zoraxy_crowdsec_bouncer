"""Assemble the verified assets from the current Actions run, never another SHA."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from verify_release import source_version

ASSETS = [
    'zoraxycrowdsecbouncer_linux_386',
    'zoraxycrowdsecbouncer_linux_amd64',
    'zoraxycrowdsecbouncer_linux_arm',
    'zoraxycrowdsecbouncer_linux_arm64',
    'zoraxycrowdsecbouncer_linux_mipsle',
    'zoraxycrowdsecbouncer_linux_riscv64',
    'zoraxycrowdsecbouncer_windows_amd64.exe',
]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

version = source_version()
assert version == os.environ['RELEASE_VERSION'], 'Release version changed'
directory = Path('dist')
expected = set(ASSETS + [name + '.sha256' for name in ASSETS])
assert {file.name for file in directory.iterdir()} == expected, 'Missing or unexpected distribution assets'
for name in ASSETS:
    path = directory / name
    assert path.stat().st_size > 0, 'Empty binary: ' + name
    assert (directory / (name + '.sha256')).read_text().split() == [digest(path), name], 'Checksum mismatch: ' + name

# Execute the Linux amd64 artifact on this runner and check full SDK metadata.
binary = directory / 'zoraxycrowdsecbouncer_linux_amd64'
binary.chmod(0o755)
actual = json.loads(subprocess.check_output([str(binary.resolve()), '-introspect']))
assert actual == json.loads(Path('.introspect').read_text(encoding='utf-8-sig')), 'Built binary introspection mismatch'
# GitHub can strip leading periods from uploaded asset names. Keep source SDK
# names intact and publish explicit portable names instead of relying on renames.
metadata_assets = {'config.yaml': 'config.yaml', '.introspect': 'introspect.json', '.releaseurl': 'releaseurl.txt', 'LICENSE': 'LICENSE'}
for source, name in metadata_assets.items():
    shutil.copyfile(source, directory / name)
    (directory / (name + '.sha256')).write_text(digest(directory / name) + '  ' + name + '\n', encoding='utf-8')

files = sorted(directory.iterdir(), key=lambda file: file.name)
(directory / 'SHA256SUMS').write_text(''.join(digest(file) + '  ' + file.name + '\n' for file in files), encoding='utf-8')
primary = ASSETS + list(metadata_assets.values())
notes = [
    '# ' + version,
    '',
    'Fork: https://github.com/yuyutti/zoraxy_crowdsec_bouncer',
    'Verified commit: `' + os.environ['GITHUB_SHA'] + '`',
    'Actions run: https://github.com/yuyutti/zoraxy_crowdsec_bouncer/actions/runs/' + os.environ['GITHUB_RUN_ID'],
    '',
    'Default: HTTP 403 with exactly Forbidden. Explicit evil configuration: HTTP 418 with 666 Evil.',
    "Evil page text: I'm a teapot. You are evil. / I refuse to serve you.",
    'This release does not deploy or restart production Zoraxy.',
    'Metadata asset names: introspect.json corresponds to .introspect; releaseurl.txt corresponds to .releaseurl.',
    'Migrate the fork Plugin ID and route tags using docs/migration.md; retain your existing config and API key.',
    'CI requires isolated Zoraxy/CrowdSec dual-stack E2E on legacy and resolved-client-IP variants. A real Cloudflare route remains unverified.',
    '',
    '| Asset | SHA256 |',
    '| --- | --- |',
]
notes += ['| ' + name + ' | `' + digest(directory / name) + '` |' for name in primary]
(directory / 'release-notes.md').write_text('\n'.join(notes) + '\n', encoding='utf-8')
print('Verified and assembled ' + str(len(list(directory.iterdir()))) + ' release assets for ' + version)

"""Check executable SDK metadata without config or external API calls."""
import json
import subprocess
from pathlib import Path

expected = json.loads(Path('.introspect').read_text())
actual = json.loads(subprocess.check_output(['go', 'run', '.', '-introspect']))
assert actual == expected, (actual, expected)
print('Introspection matches .introspect')

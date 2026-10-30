"""Isolated Compose E2E; invokes only this repository's test containers.
No global decision deletion: cleanup selects this run's unique reason.
Requires Linux Docker with IPv6 enabled; an unavailable family is a failure.
"""
import ipaddress
import json
import subprocess
import time
import uuid
from pathlib import Path

COMPOSE = ['docker', 'compose']
CONFIG = Path('build/plugins/zoraxycrowdsecbouncer/config.yaml')
reason = 'fork-e2e-' + uuid.uuid4().hex

def run(*args, check=True):
    result = subprocess.run(COMPOSE + list(args), check=check, capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError('Compose operation failed')
    return result.stdout

def cli(*args):
    return run('exec', '-T', 'crowdsec', 'cscli', *args)

def wait_lapi():
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            cli('lapi', 'status')
            return
        except subprocess.CalledProcessError:
            time.sleep(1)
    raise RuntimeError('Test LAPI did not become ready')

def start_lapi():
    run('start', 'crowdsec')
    wait_lapi()

def request(family, *headers):
    args = ['exec', '-T', 'test_client', 'curl', '-' + str(family), '--max-time', '5', '-ksS', '--connect-to', 'localhost:443:zoraxy:443', '-H', 'Host: localhost']
    for header in headers:
        args += ['-H', header]
    result = run(*args, '-w', '\n%{http_code} %{local_ip}', 'https://localhost/')
    body, _, metadata = result.rpartition('\n')
    code, source = metadata.split()
    expected = '172.30.88.20' if family == 4 else 'fd72:30:88::20'
    assert ipaddress.ip_address(source) == ipaddress.ip_address(expected), (source, expected)
    return int(code), body

def expect(family, code, fragment, *headers):
    deadline = time.monotonic() + 45
    last = None
    while time.monotonic() < deadline:
        try:
            last = request(family, *headers)
            if last[0] == code and fragment in last[1]:
                return
        except subprocess.CalledProcessError as error:
            # Only this fixed test curl command reaches here; include bounded
            # transport errors, never configuration files or request credentials.
            last = ('curl-exit-' + str(error.returncode), (error.stderr or '')[:256])
        except ValueError:
            last = ('invalid-curl-metadata', '')
        time.sleep(1)
    raise AssertionError((family, code, fragment, None if last is None else (last[0], last[1][:256])))

def decision_ids(value):
    if isinstance(value, dict):
        if value.get('scenario') == reason and 'id' in value:
            yield value['id']
        for child in value.values():
            yield from decision_ids(child)
    elif isinstance(value, list):
        for child in value:
            yield from decision_ids(child)

def cleanup_decisions():
    data = json.loads(cli('decisions', 'list', '-o', 'json'))
    for decision_id in set(decision_ids(data)):
        cli('decisions', 'delete', '--id', str(decision_id))

def ban(ip, duration='2m'):
    cli('decisions', 'add', '--ip', ip, '--duration', duration, '--reason', reason)

original = CONFIG.read_bytes()
try:
    run('--profile', 'e2e', 'up', '-d', 'test_client')
    # Verify the container did not migrate our modern bootstrap as a legacy file.
    run('exec', '-T', 'zoraxy', 'python3', '-c',
        "import json; p=json.load(open('/opt/zoraxy/config/conf/proxy/localhost.config')); "
        "assert p['ProxyType']==1 and p['RootOrMatchingDomain']=='localhost'; "
        "assert p['ActiveOrigins'][0]['OriginIpOrDomain']=='crowdsec-bouncer-test-webserver:5678'; "
        "assert p['Tags']==['protected']")
    print('Checking actual IPv4/IPv6 HTTPS pass-through', flush=True)
    for family in (4, 6):
        expect(family, 200, 'E2E test server is reachable')
    print('Checking default BAN and forged headers', flush=True)
    ban('172.30.88.20')
    expect(4, 403, 'Forbidden')
    expect(4, 403, 'Forbidden', 'CF-Connecting-IP: 198.51.100.1', 'X-Real-IP: invalid', 'X-Forwarded-For: 198.51.100.1')
    ban('fd72:30:88::20')
    expect(6, 403, 'Forbidden')
    print('Checking evil response, outage and recovery', flush=True)
    CONFIG.write_bytes(original + b'\nblock_response:\n    status_code: 418\n    page: evil\n')
    run('restart', 'zoraxy')
    expect(4, 418, '666 Evil')
    expect(6, 418, '666 Evil')
    run('stop', 'crowdsec')
    expect(4, 418, '666 Evil')
    start_lapi()
    cleanup_decisions()
    expect(4, 200, 'E2E test server is reachable')
    expect(6, 200, 'E2E test server is reachable')
    print('Checking local expiry during LAPI outage', flush=True)
    ban('172.30.88.20', '15s')
    expect(4, 418, '666 Evil')
    run('stop', 'crowdsec')
    expect(4, 200, 'E2E test server is reachable')
    start_lapi()
    print('Checking custom fallback and public RPC isolation', flush=True)
    CONFIG.write_bytes(original + b'\nblock_response:\n    page: custom\n    custom_page: ./missing-e2e.html\n')
    ban('172.30.88.20')
    run('restart', 'zoraxy')
    expect(4, 403, 'Forbidden')
    cleanup_decisions()
    expect(4, 200, 'E2E test server is reachable')
    # Public routing must never expose internal UI/RPC, even with a forged UUID.
    for path in ('/api/config-status', '/d_sniff/', '/d_capture/'):
        result = run('exec', '-T', 'test_client', 'curl', '-4', '-ksS', '--max-time', '5', '--connect-to', 'localhost:443:zoraxy:443', '-H', 'Host: localhost', '-H', 'X-Zoraxy-RequestID: fixture', 'https://localhost' + path)
        assert 'E2E test server is reachable' in result, path
    print('Compose E2E passed: explicit IPv4/IPv6 source checks, default, evil, removal, expiry, outage, spoofing, custom fallback, public RPC isolation')
finally:
    run('start', 'crowdsec', check=False)
    try:
        wait_lapi()
        cleanup_decisions()
    finally:
        CONFIG.write_bytes(original)
        run('restart', 'zoraxy', check=False)

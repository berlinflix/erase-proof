"""Exercise real block I/O in a disposable QEMU guest, never a host device.

The only writable guest disk is a freshly generated 64 MiB file. No NIC, host
block passthrough, USB passthrough or existing writable image can be requested.
The temporary guest's serial debug shell runs this controlled acceptance test;
the release ISO's default boot configuration is unchanged.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('iso', type=Path)
parser.add_argument('--kernel', type=Path, required=True)
parser.add_argument('--initrd', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--protocol', choices=['ide-overwrite', 'nvme-format'], default='ide-overwrite')
args = parser.parse_args()
if not all(p.is_file() for p in (args.iso, args.kernel, args.initrd)):
    parser.error('Provide the built ISO, kernel and initrd. No target device argument is supported.')
args.output.mkdir(parents=True, exist_ok=False)
output = args.output.resolve()


def run(*arguments):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError((result.stdout+result.stderr).decode(errors='replace')[-4000:])
    return result.stdout


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(4*1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


guest_template = r'''
import hashlib,json,subprocess,tempfile
from pathlib import Path
configuration = CONFIGURATION
app = '/opt/eraseproof/EraseProof'
def cli(*arguments):
    result = subprocess.run([app, '--cli', *map(str, arguments)], capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(result.stderr[-4000:])
    return json.loads(result.stdout)
def checksum(path):
    digest = hashlib.sha256()
    with open(path, 'rb', buffering=0) as source:
        for chunk in iter(lambda: source.read(4*1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()
try:
    subprocess.run(['udevadm', 'settle', '--timeout=30'], check=True, timeout=35)
    matches = [d for d in cli('devices') if (d.get('serial') or '').strip() == configuration['serial']]
    assert len(matches) == 1, 'The unique generated test disk was not found.'
    device = matches[0]
    assert device['type'] == 'disk' and int(device['size']) == configuration['size']
    assert 'qemu' in (device.get('model') or '').lower()
    path = device['name']
    prepared = cli('plan', path, '--allow-device', path, '--confirm', configuration['serial'])
    assert prepared['target']['kind'] == 'virtual-block-device'
    assert checksum(path) == configuration['before_sha256']
    with tempfile.TemporaryDirectory(prefix='eraseproof-secondary-') as temporary:
        root = Path(temporary)
        recovered = cli('recover', path, '--mode', 'deleted', '--output', root/'recovered')
        assert configuration['original_sha256'] in {f['sha256'] for f in recovered['candidates']}
        assert checksum(path) == configuration['before_sha256'], 'Read-only recovery changed the source.'
        references = root/'references.json'
        references.write_text(json.dumps(configuration['references']))
        if configuration['protocol'] == 'nvme-format':
            controllers = [p for p in Path('/sys/class/nvme').iterdir()
                           if (p/'serial').read_text().strip() == configuration['serial']]
            assert len(controllers) == 1
            controller = '/dev/'+controllers[0].name
            planned = cli('nvme-format-plan', controller, '--method', 'user-data', '--allow-controller', controller,
                          '--confirm', configuration['serial'])
            assert all(c['ses'] == 1 for c in planned['commands'])
            receipt = cli('nvme-format-submit', controller, '--method', 'user-data', '--allow-controller', controller,
                          '--confirm', configuration['serial'], '--case', root/'evidence')
            assert receipt['payload']['state'] == 'firmware-reports-completion'
            assert not receipt['payload']['certificate_issued']
            receipt_path = root/'receipt.json'
            receipt_path.write_text(json.dumps(receipt))
            assert cli('record', receipt_path, '--trusted-fingerprint', receipt['signer_fingerprint'])['trusted_signer']
            # Check Format's own result before any subsequent overwrite. This
            # cannot be manufactured by exercising the existing overwrite path.
            assert checksum(path) == configuration['expected_zero_sha256']
            result = cli('verify', path, '--references', references)
            assert result['passed'] and result['rrs'] == 0
            attacked = cli('attack', path, '--output', root/'post-format-attack')
            assert attacked['recovered_files'] == 0
            tools = {t['tool']: t['status'] for t in attacked['tools']}
            assert tools['PhotoRec'] == tools['bulk_extractor'] == 'completed'
            report = {'passed': True, 'protocol': 'nvme-format', 'source_recovery_exact': True,
                      'device_model': device['model'], 'serial': configuration['serial'],
                      'recovery_source_unchanged': True, 'native_format_ioctl': True,
                      'format_ses': 1, 'format_full_zero_readback': True,
                      'signed_receipt_valid': True, 'firmware_receipt_certificate_issued': False,
                      'independent_tools': tools,
                      'audit_intact': cli('audit', root/'evidence')['intact']}
            print('RESULT_MARKER'+json.dumps(report, separators=(',', ':')), flush=True)
            raise SystemExit(0)
        erased = cli('erase', path, '--allow-device', path, '--confirm', configuration['serial'],
                     '--references', references, '--case', root/'evidence')
        record = erased['record']
        result = record['payload']['verification']
        assert result['passed'] and result['rrs'] == 0
        assert result['bytes_checked'] == configuration['size']
        assert result['io']['direct_bytes'] == configuration['size']
        assert result['independent_attack']['passed']
        assert cli('record', erased['certificate'], '--trusted-fingerprint', record['signer_fingerprint'])['trusted_signer']
        assert cli('audit', root/'evidence')['intact']
        report = {'passed': True, 'device_model': device['model'], 'serial': configuration['serial'],
                  'source_recovery_exact': True, 'recovery_source_unchanged': True,
                  'rrs_after_overwrite': result['rrs'], 'direct_bytes': result['io']['direct_bytes'],
                  'signed_record_valid': True, 'audit_intact': True,
                  'independent_tools': result['independent_attack']['required_tools'],
                  'metadata_gate': result['independent_attack']['metadata_gate']}
except Exception as error:
    report = {'passed': False, 'error': str(error)}
print('RESULT_MARKER'+json.dumps(report, separators=(',', ':')), flush=True)
'''

with tempfile.TemporaryDirectory(prefix='eraseproof-qemu-block-') as temporary:
    managed = Path(temporary).resolve()
    image, original = managed/'disposable.img', managed/'fresh.custom'
    size = 64*1024*1024
    with image.open('xb') as target:
        target.truncate(size)
    # All formatting/deletion takes place in the file just created above.
    run('mkfs.fat', '-F', '32', image)
    original.write_bytes(os.urandom(41379))
    name = 'fresh-'+uuid.uuid4().hex[:8]+'.custom'
    run('mcopy', '-i', image, original, '::/'+name)
    run('mdel', '-i', image, '::/'+name)
    data = original.read_bytes()
    configuration = {'serial': 'EPQA'+uuid.uuid4().hex[:12], 'size': size, 'protocol': args.protocol,
                     'expected_zero_sha256': hashlib.sha256(bytes(size)).hexdigest(),
                     'before_sha256': sha(image), 'original_sha256': sha(original),
                     'references': {'block_size': 512,
                         'block_hashes': sorted({hashlib.sha256(data[n:n+512]).hexdigest() for n in range(0, len(data)-511, 512)}),
                         'metadata_patterns': [name.encode().hex(), name.encode('utf-16-le').hex()],
                         'file_hashes': [sha(original)]}}
    nonce = uuid.uuid4().hex
    ready, marker = 'EP_READY_'+nonce, 'EP_BLOCK_RESULT_'+nonce+':'
    guest = guest_template.replace('CONFIGURATION', repr(configuration)).replace('RESULT_MARKER', marker)
    encoded = base64.b64encode(gzip.compress(guest.encode())).decode()
    command_lines = ['cat > /tmp/ep-block-test.b64 <<\'EP_END_'+nonce+'\'']
    command_lines.extend(encoded[n:n+1000] for n in range(0, len(encoded), 1000))
    command_lines.extend(['EP_END_'+nonce,
                          'base64 -d /tmp/ep-block-test.b64 | gzip -d > /tmp/ep-block-test.py',
                          'python3 /tmp/ep-block-test.py', ''])
    command = ['qemu-system-x86_64', '-name', 'EraseProof-disposable-block-test', '-accel', 'kvm',
               '-cpu', 'host', '-m', '4096', '-smp', '2', '-display', 'none', '-vga', 'std',
               '-nic', 'none', '-no-reboot', '-serial', 'stdio', '-monitor', 'none',
               '-cdrom', str(args.iso.resolve()),
               '-drive', f'file={image},format=raw,if=none,id=epdisk',
               '-device', (f'nvme,drive=epdisk,serial={configuration["serial"]}' if args.protocol == 'nvme-format'
                           else f'ide-hd,drive=epdisk,bus=ide.0,unit=0,serial={configuration["serial"]}'),
               '-kernel', str(args.kernel.resolve()), '-initrd', str(args.initrd.resolve()),
               '-append', 'boot=casper quiet username=eraseproof hostname=eraseproof noprompt noeject '
                          'systemd.debug_shell=ttyS0 systemd.mask=serial-getty@ttyS0.service console=tty0 console=ttyS0,115200n8']
    report, sent, last_probe, buffer = None, False, 0, b''
    started = time.monotonic()
    with (output/'serial.log').open('xb') as log, (output/'qemu.log').open('xb') as errors:
        vm = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        try:
            while time.monotonic()-started < 300:
                elapsed = time.monotonic()-started
                if vm.poll() is not None:
                    raise RuntimeError('QEMU exited before the test result; inspect qemu.log.')
                if not sent and elapsed > 15 and elapsed-last_probe > 5:
                    vm.stdin.write(("printf '\\n"+ready+"\\n'\n").encode())
                    vm.stdin.flush()
                    last_probe = elapsed
                if not select.select([vm.stdout], [], [], 1)[0]:
                    continue
                chunk = os.read(vm.stdout.fileno(), 65536)
                log.write(chunk)
                log.flush()
                if log.tell() > 16*1024*1024:
                    raise RuntimeError('Guest console exceeded the controlled log limit.')
                buffer = (buffer+chunk)[-128*1024:]
                clean = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', buffer.decode(errors='replace')).replace('\r', '')
                lines = clean.splitlines(keepends=True)
                if not sent and ready in (line.strip() for line in lines):
                    vm.stdin.write(('\n'.join(command_lines)).encode())
                    vm.stdin.flush()
                    sent = True
                result = next((line[len(marker):] for line in lines if line.startswith(marker) and line.endswith('\n')), None)
                if result is not None:
                    report = json.loads(result)
                    break
            if report is None:
                raise RuntimeError('Guest acceptance timed out; inspect serial.log.')
        except Exception as error:
            report = {'passed': False, 'error': str(error)}
        finally:
            vm.terminate()
            try:
                vm.wait(timeout=10)
            except subprocess.TimeoutExpired:
                vm.kill()
                vm.wait(timeout=5)
    report.update({'iso_sha256': sha(args.iso), 'generated_writable_disks': 1,
                   'existing_or_physical_disks_attached': 0, 'network_devices': 0,
                   'host_disk_bytes': size, 'host_disk_sha256_before': configuration['before_sha256'],
                   'host_disk_sha256_after': sha(image), 'virtualbox_tested': False})
    with image.open('rb') as source:
        report['host_file_complete_zero_readback'] = all(not any(chunk) for chunk in iter(lambda: source.read(4*1024*1024), b''))
    report['passed'] &= report['host_file_complete_zero_readback']
    (output/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    if not report['passed']:
        raise SystemExit(1)

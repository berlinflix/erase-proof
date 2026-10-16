"""Confirmed ATA erase/attack/escalate/certify workflow.

Only an observed busy-to-success sanitize transition permits automatic progress.
ATA status lacks NVMe's action log: a stale success bit never proves completion
of a newly submitted action. Interrupted or ambiguous commands require manual
status inspection and never cause an automatic retry.
"""
import json
import os
import time
import uuid

from . import ata, attackgate, engine, media, workflow
from .carve import checkpoint
from .evidence import EvidenceStore, digest, now
from .models import EraseProofError

METHODS = ('sanitize-crypto', 'sanitize-block', 'enhanced-secure-erase', 'logical-overwrite')


def identity(discovery):
    info = discovery['ata']
    return (info['serial'], info['model'], info['sector_bytes'], info['dco_sectors'])


def plan(discovery, methods, allow_device, confirmation, open_hidden=False, capacity_sectors=None):
    if not methods or len(methods) > 4 or len(set(methods)) != len(methods) or any(m not in METHODS for m in methods):
        raise EraseProofError('Select one through four distinct supported ATA methods in their confirmed order.')
    if 'logical-overwrite' in methods and methods[-1] != 'logical-overwrite':
        raise EraseProofError('Logical overwrite must be the final ATA workflow method.')
    target, info = discovery['target'], discovery['ata']
    steps = []
    for method in methods:
        if method == 'logical-overwrite':
            # Reuse the ATA identity/hidden-range/security gates without
            # submitting a firmware erase. The host overwrite gate runs again
            # immediately before writes, after any explicit expansion.
            if allow_device != target['path'] or confirmation != info['serial'] or not confirmation:
                raise EraseProofError('Exact ATA allowlist and serial confirmation are required.')
            if info['security']['locked'] or info['security']['enabled'] or info['security']['expired']:
                raise EraseProofError('ATA security must be disabled and unlocked before logical overwrite.')
            status = info.get('sanitize_status', {})
            if info['sanitize_supported'] and ('busy' not in status or status['busy']):
                raise EraseProofError('ATA sanitize status is busy or unknown; logical overwrite is blocked.')
            if info['visible_sectors'] != info['dco_sectors']:
                ata.plan(discovery, 'open-hidden', allow_device, confirmation, open_hidden, capacity_sectors)
            step = {'method': method, 'bytes': info['dco_sectors']*info['sector_bytes'],
                    'scope': 'Entire verified factory-visible logical range; full direct overwrite and independent attacks.'}
        else:
            step = ata.plan(discovery, method, allow_device, confirmation, open_hidden, capacity_sectors)
        steps.append(step)
    return {'target': target, 'serial': info['serial'], 'model': info['model'],
            'factory_sectors': info['dco_sectors'], 'sector_bytes': info['sector_bytes'], 'steps': steps,
            'open_hidden': info['visible_sectors'] != info['dco_sectors'], 'read_only': True,
            'scope': 'Complete explicitly confirmed ATA factory range. Logical recovery evidence; physical remanence remains unverified.',
            'escalation': 'Only completed operations and complete attacks with observed residue advance to another pre-confirmed method. Unknown status, stale sanitize success and identity changes stop.'}


def same_complete_device(discovery, prepared):
    info, target = discovery['ata'], discovery['target']
    if ((info['serial'], info['model'], info['sector_bytes'], info['dco_sectors']) !=
            (prepared['serial'], prepared['model'], prepared['sector_bytes'], prepared['factory_sectors'])
            or info['visible_sectors'] != prepared['factory_sectors']
            or info['native_sectors'] != prepared['factory_sectors']
            or target['size'] != prepared['factory_sectors']*prepared['sector_bytes']):
        raise EraseProofError('ATA identity or visible/native/factory capacity changed; stop and inspect the disk before retrying.')


def wait(path, prepared, receipt, timeout, store, job, cancel=None, progress=None):
    deadline = time.monotonic()+timeout
    status = receipt['payload']['after'].get('sanitize_status', {})
    observed_busy, previous = bool(status.get('busy')), None
    while True:
        checkpoint(cancel)
        discovery = ata.probe(path)
        same_complete_device(discovery, prepared)
        status = discovery['ata'].get('sanitize_status', {})
        if status != previous:
            store.append('workflow.ata-status', {'job': job, 'status': status})
            previous = status
        if 'flags' not in status or status.get('frozen'):
            raise EraseProofError('ATA sanitize status is unknown or frozen; no automatic retry.')
        if status.get('busy'):
            observed_busy = True
        elif not observed_busy:
            raise EraseProofError('ATA sanitize completion cannot be correlated with this submission: no busy transition observed. Inspect manually; no automatic retry.')
        elif status.get('last_success'):
            return discovery
        else:
            raise EraseProofError('ATA sanitize ended without success; no automatic retry.')
        if time.monotonic() >= deadline:
            raise EraseProofError('ATA sanitize wait expired. Firmware may continue; no automatic retry.')
        if progress:
            progress('Firmware', min(1, status.get('progress_raw', 0)/65536), 'ATA sanitize is running; cancellation stops only this wait.')
        time.sleep(.5)


def run(path, methods, allow_device, confirmation, evidence_dir, references, *, open_hidden=False,
        capacity_sectors=None, timeout=3600, cancel=None, progress=None):
    if os.geteuid() != 0:
        raise EraseProofError('ATA workflows require an explicit root CLI invocation.')
    refs = engine.validate_references(references)
    if not (refs['block_hashes'] or refs['block_hashes_4096'] or refs['metadata_patterns']):
        raise EraseProofError('Retained target fingerprint/reference baseline is required before any erasure.')
    if not 1 <= timeout <= 86400:
        raise EraseProofError('Firmware wait timeout must be between 1 and 86400 seconds.')
    initial = ata.probe(path)
    prepared = plan(initial, methods, allow_device, confirmation, open_hidden, capacity_sectors)
    _, root = ata.device_gate(path, allow_device, confirmation, writing=True)
    media.outside_devices(evidence_dir, [root])
    attackgate.require_tools()
    store = EvidenceStore(evidence_dir)
    if not store.check():
        raise EraseProofError('Audit history is damaged; no ATA workflow command submitted.')
    store.key()
    job, rounds = 'ata-workflow-'+uuid.uuid4().hex, []
    store.append('workflow.started', {'job': job, 'plan': prepared, 'references_sha256': digest(refs)})
    try:
        for index, method in enumerate(methods):
            checkpoint(cancel)
            fresh = ata.probe(path)
            if identity(fresh) != identity(initial):
                raise EraseProofError('ATA device identity or factory capacity changed; escalation blocked.')
            ata.device_gate(path, allow_device, confirmation, writing=True)
            if method == 'logical-overwrite':
                if fresh['ata']['visible_sectors'] != prepared['factory_sectors']:
                    ata.submit(path, 'open-hidden', allow_device, confirmation, evidence_dir, open_hidden, capacity_sectors,
                               expected_identity=identity(initial))
                fresh = ata.probe(path)
                same_complete_device(fresh, prepared)
                receipt = engine.erase(path, confirmation, evidence_dir, refs, allow_device, progress, cancel,
                                       host_device=True, expected_target=fresh['target'])
            else:
                receipt = ata.submit(path, method, allow_device, confirmation, evidence_dir, open_hidden, capacity_sectors,
                                     expected_identity=identity(initial))
                if method.startswith('sanitize-'):
                    wait(path, prepared, receipt, timeout, store, job, cancel, progress)
                elif receipt['payload']['state'] != 'firmware-reports-completion':
                    raise EraseProofError('ATA firmware completion is uncertain; no automatic retry.')
            fresh = ata.probe(path)
            same_complete_device(fresh, prepared)
            expected = {'name': path, 'size': fresh['target']['size'], 'serial': prepared['serial'], 'model': prepared['model']}
            finding = workflow.attack_namespace(path, refs, store.root/(job+f'.round-{index}.attack'), cancel, progress, expected)
            measured = {'method': method, 'receipt': receipt, 'findings': [finding]}
            rounds.append(measured)
            store.append('workflow.round', {'job': job, **measured})
            same_complete_device(ata.probe(path), prepared)
            result = finding['verification']
            if result['passed']:
                verification = {'passed': True, 'rrs': 0, 'bytes_checked': result['bytes_checked'],
                                'independent_attack': {'passed': True}, 'rounds': rounds,
                                'all_filesystem_copies_verified': False, 'hidden_capacity_rechecked': True}
                record = store.certify({'schema': 'eraseproof.native-evidence.v1', 'id': job, 'issued_at': now(),
                    'target': fresh['target'], 'plan': prepared, 'verification': verification,
                    'assurance': 'Complete logical readback and independent recovery attacks over the confirmed factory range. Physical firmware/remanence and standards conformance remain unverified.'})
                with (store.root/(job+'.json')).open('x') as output:
                    json.dump(record, output, indent=2)
                return record
            if not result['attacks_completed'] or not result['observed_residue']:
                raise EraseProofError('ATA attack is incomplete or inconclusive; automatic escalation is blocked.')
            store.append('workflow.escalating', {'job': job, 'completed_method': method,
                         'next_method': methods[index+1] if index+1 < len(methods) else None})
        raise EraseProofError('All confirmed ATA methods were attempted and residue remains. No erasure certificate issued.')
    except BaseException as error:
        store.append('workflow.incomplete', {'job': job, 'reason': str(error), 'completed_rounds': len(rounds)})
        raise

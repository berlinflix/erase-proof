"""Explicit controller-wide Discover/Plan/Erase/Attack/Certify escalation.

Only the pre-confirmed controller and namespace set may be touched. Timeouts,
unknown status, changed identity and incomplete attacks never trigger a retry.
"""
import json
import time
import uuid

from . import attackgate, media, nvmeformat
from .carve import checkpoint
from .engine import hash_stream, validate_references, verify
from .evidence import EvidenceStore, digest, now
from .models import EraseProofError
from .targets import open_target


def plan(probe, methods, allow_controller, confirmation):
    if not methods or len(methods) > 4 or len(set(methods)) != len(methods):
        raise EraseProofError('Select one through four distinct methods in their intended escalation order.')
    steps = []
    for method in methods:
        if method in ('crypto-erase', 'block-erase'):
            step = media.nvme_plan(probe, method, allow_controller, confirmation)
        elif method in ('format-crypto', 'format-user-data'):
            step = nvmeformat.plan(probe, method.removeprefix('format-'), allow_controller, confirmation)
        else:
            raise EraseProofError('Unsupported controller workflow method.')
        steps.append(step)
    return {'controller': probe['path'], 'serial': probe['serial'], 'model': probe['model'],
            'namespace_ids': probe['namespace_ids'], 'namespaces': probe['namespaces'], 'steps': steps,
            'read_only': True, 'scope': probe['scope'],
            'escalation': 'Advance only after completed firmware status plus completed attacks report observed residue. Never retry an uncertain command, failed scanner or changed controller.'}


def wait(controller, serial, timeout, store, job, cancel=None, progress=None, expected_action=None):
    deadline, previous = time.monotonic()+timeout, None
    while True:
        checkpoint(cancel)
        status = media.nvme_status(controller)
        if status['serial'] != serial:
            raise EraseProofError('Controller identity changed while waiting for firmware completion.')
        state = status['state']
        command_dword = status.get('log', {}).get('scdw10')
        if expected_action is not None and (command_dword is None or media.number(command_dword) & 7 != expected_action):
            raise EraseProofError('Sanitize log does not identify the submitted action; completion is uncertain and no retry is allowed.')
        if state != previous:
            store.append('workflow.firmware-status', {'job': job, 'status': status})
            previous = state
        if state in ('firmware-reports-success', 'success-with-deallocation'):
            return status
        if state != 'in-progress':
            raise EraseProofError('Firmware status is failed, unknown or not correlated with a submitted operation. No automatic retry.')
        if time.monotonic() >= deadline:
            raise EraseProofError('Firmware completion wait expired. The drive may continue; inspect status before any retry.')
        if progress:
            progress('Firmware', status['progress'], 'Firmware is running; cancelling the wait cannot stop the device command.')
        time.sleep(.5)


def attack_namespace(path, refs, folder, cancel=None, progress=None):
    with open_target(path, writable=True) as source:
        from .targets import describe
        target = describe(path)
        result = verify(path, refs, progress, cancel, source, target['size'])
        independent = attackgate.check(path, folder, refs, stream=source, length=target['size'],
            expected_sha256=result['sha256'], zero_readback=result['nonzero_bytes'] == 0, progress=progress, cancel=cancel)
        result['independent_attack'] = independent
        completed = all(value == 'completed' for key, value in independent['required_tools'].items() if key != 'Sleuth Kit')
        completed &= independent['metadata_gate'] == 'superseded-by-complete-zero-readback' or independent['required_tools']['Sleuth Kit'] == 'completed'
        result['attacks_completed'] = bool(completed)
        result['passed'] &= independent['passed']
        result['rrs'] = max(result['rrs'] or 0, independent['target_reference_matches']/max(1, result['reference_count']))
        result['observed_residue'] = bool(result['nonzero_bytes'] or result['matched_reference_blocks'] or result['metadata_residues'] or independent['target_reference_matches'])
        return {'target': target, 'verification': result}


def run(controller, methods, allow_controller, confirmation, evidence_dir, references, *, timeout=3600, cancel=None, progress=None):
    import os
    if os.geteuid() != 0:
        raise EraseProofError('A verified controller workflow requires an explicit root CLI invocation.')
    refs = validate_references(references)
    if not (refs['block_hashes'] or refs['block_hashes_4096'] or refs['metadata_patterns']):
        raise EraseProofError('A retained target fingerprint/reference baseline is required before the workflow can erase or certify.')
    if not 1 <= timeout <= 86400:
        raise EraseProofError('Firmware wait timeout must be between 1 and 86400 seconds.')
    initial = media.nvme_probe(controller)
    prepared = plan(initial, methods, allow_controller, confirmation)
    media.outside_devices(evidence_dir, [n['device'] for n in initial['namespaces']])
    attackgate.require_tools()
    store = EvidenceStore(evidence_dir)
    if not store.check():
        raise EraseProofError('Audit history is damaged; no workflow command submitted.')
    store.key()
    job, rounds = 'workflow-'+uuid.uuid4().hex, []
    store.append('workflow.started', {'job': job, 'plan': prepared, 'references_sha256': digest(refs)})
    try:
        for index, method in enumerate(methods):
            checkpoint(cancel)
            fresh = media.nvme_probe(controller)
            if digest(plan(fresh, methods[index:], allow_controller, confirmation)['namespaces']) != digest(prepared['namespaces']) or fresh['namespace_ids'] != prepared['namespace_ids']:
                raise EraseProofError('Namespace identity or capacity changed; escalation blocked.')
            if method.startswith('format-'):
                receipt = nvmeformat.submit(controller, method.removeprefix('format-'), allow_controller, confirmation, evidence_dir,
                                            expected_namespaces=prepared['namespaces'])
            else:
                receipt = media.submit_nvme(controller, method, allow_controller, confirmation, evidence_dir,
                                            expected_namespaces=prepared['namespaces'])
                wait(controller, confirmation, timeout, store, job, cancel, progress, 4 if method == 'crypto-erase' else 2)
            findings = []
            for namespace in initial['namespaces']:
                checkpoint(cancel)
                findings.append(attack_namespace(namespace['device']['name'], refs,
                    store.root/(job+f'.round-{index}.ns-{namespace["id"]}'), cancel, progress))
            measured = {'method': method, 'receipt': receipt, 'findings': findings}
            rounds.append(measured)
            store.append('workflow.round', {'job': job, **measured})
            if all(f['verification']['passed'] for f in findings):
                result = {'passed': True, 'rrs': 0, 'bytes_checked': sum(f['verification']['bytes_checked'] for f in findings),
                          'independent_attack': {'passed': True}, 'rounds': rounds, 'scope': prepared['scope'],
                          'all_filesystem_copies_verified': False}
                record = store.certify({'schema': 'eraseproof.native-evidence.v1', 'id': job, 'issued_at': now(),
                    'target': {'kind': 'nvme-controller', 'path': controller, 'serial': confirmation, 'model': prepared['model']},
                    'plan': prepared, 'verification': result,
                    'assurance': 'Full logical namespace readback and independent attack evidence. Firmware/physical remanence and standard compliance remain unverified.'})
                with (store.root/(job+'.json')).open('x') as output:
                    json.dump(record, output, indent=2)
                return record
            if not all(f['verification']['attacks_completed'] for f in findings):
                raise EraseProofError('An independent attack was incomplete; automatic escalation is blocked.')
            if not any(f['verification']['observed_residue'] for f in findings):
                raise EraseProofError('Verification did not establish a clean result or observed residue; no automatic retry.')
            store.append('workflow.escalating', {'job': job, 'completed_method': method,
                         'next_method': methods[index+1] if index+1 < len(methods) else None})
        raise EraseProofError('Every confirmed method was attempted and residue remains. No erasure certificate issued.')
    except BaseException as error:
        store.append('workflow.incomplete', {'job': job, 'reason': str(error), 'completed_rounds': len(rounds)})
        raise

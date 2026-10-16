"""Explainable structural confidence, without treating entropy as authenticity."""
from collections import Counter
import math


def profile(path, candidate, validation, cancel=None):
    count, total, samples = Counter(), 0, []
    with open(path, "rb") as source:
        while data := source.read(65536):
            from .carve import checkpoint
            checkpoint(cancel)
            count.update(data)
            total += len(data)
            frequencies = Counter(data)
            entropy = -sum((n/len(data))*math.log2(n/len(data)) for n in frequencies.values())
            if len(samples) < 4096:
                samples.append(round(entropy, 4))
    entropy = -sum((n/total)*math.log2(n/total) for n in count.values()) if total else 0.0
    valid = validation["status"] == "valid"
    incomplete = candidate.method == "pdf-earlier-revision"
    metadata = candidate.method in ('sleuthkit-metadata', 'ext4-journal-inode')
    complete = total == candidate.length and not incomplete and (not metadata or valid)
    plausibility = total == 0 or len(count) > 1
    # Preserve structural confidence ceiling. Entropy can reduce a suspicious
    # score; high entropy alone never raises it, nor proves original content.
    validation_points = 50 if valid else 25 if validation["status"] == "structural-only" else 10
    completeness_points = 30 if complete else 10
    structural_points = 18 if candidate.confidence >= 90 else max(0, candidate.confidence-80)
    if metadata:
        structural_points = 18 if candidate.method == 'ext4-journal-inode' else 10
    score = min(candidate.confidence, validation_points+completeness_points+structural_points)
    if not plausibility and total:
        score = min(score, 35)
    if candidate.method == "bifragment-gap-reconstruction" and candidate.file_type in ("JPEG", "PDF"):
        score = min(score, 60)
    return {"score": score, "scale": "0-100 structural heuristic, not probability of exact original recovery",
            "validation": validation["status"], "structural_completeness": complete,
            "components": {"validation": validation_points, "completeness": completeness_points,
                           "structure": structural_points, "entropy_penalty": 0 if plausibility else 63},
            "entropy_bits_per_byte": round(entropy, 6), "entropy_window_bytes": 65536,
            "entropy_samples": samples, "entropy_samples_truncated": total > 4096*65536,
            "authenticity": "No ground truth; a decoded or high-entropy file can still contain incorrect content"}


def enrich_metadata(candidate, cancel=None):
    from .validators import isolated
    family = {'JPG': 'JPEG'}.get(candidate.file_type, candidate.file_type)
    supported = family in ('PNG', 'JPEG', 'GIF', 'BMP', 'PDF', 'SQLITE', 'ZIP', 'DOCX', 'XLSX', 'PPTX')
    validation = isolated(candidate.output, family) if supported else {'status': 'not-validated', 'detail': 'No structural validator for this recovered format; original byte identity is unproven'}
    candidate.confidence = 98 if validation['status'] == 'valid' else min(35, candidate.confidence or 40)
    if not candidate.length:
        candidate.confidence = 0
    candidate.evidence.append(validation['detail'])
    candidate.confidence_details = profile(candidate.output, candidate, validation, cancel)
    candidate.confidence_details['original_size_verified'] = False
    candidate.confidence = candidate.confidence_details['score']
    return candidate

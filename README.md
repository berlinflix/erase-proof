# EraseProof

A polished, working first implementation of the EraseProof proposal: a browser-local disk-image workbench built around **Discover → Plan → Erase → Attack → Certify**.

## Run

Requires Node.js 20 or later. No package installation or build step is needed.

```sh
npm run dev
# Open http://127.0.0.1:4173
npm test
```

The hosted version uses the same `dist/` files. Hosting identity lives in `.openai/hosting.json`.

## Implemented

- Three real 8/4/2 MiB fixture images with known PDFs, PNGs, older copies, filenames and block fingerprints.
- Raw image import, inspection, SHA-256 hashing and download. Maximum 128 MiB per image, 256 MiB per workspace.
- Contiguous PNG/PDF/JPEG/ZIP carving with downloadable candidates and an exportable manifest. PNG chunk CRCs are checked; other format scores reflect boundary checks, not complete semantic validation.
- Complete zero overwrite of the selected workspace image, followed by complete byte read-back, signature carving, known 4 KiB block search and known filename search.
- Separate read-only image verification.
- Fixture RRS calculated from unique known block fingerprints and known filenames. Imported images explicitly show RRS as unavailable because they have no ground-truth reference set.
- ECDSA P-256 / SHA-256 self-signed JSON records with offline signature verification in the app and printable evidence.
- SHA-256 hash-chained audit events and audit export.
- IndexedDB persistence. Image replacement, record creation and audit append commit in one transaction. Conflicting history updates from other tabs fail rather than silently overwrite the audit chain.
- Web Worker processing, cancellation, confirmation before workspace-image replacement, keyboard-accessible dialogs, reduced-motion support, and responsive layouts.

## Scope of the evidence

This version operates on the bytes of a **workspace image**. It does not access or sanitize physical devices, modify an imported original, parse filesystems, invoke PhotoRec/Sleuth Kit, run privileged Linux commands, or remove snapshots, browser storage remnants or flash/FTL residue. Zero image read-back does not prove physical-device erasure.

Records are self-signed using a browser-generated non-exportable private key, persisted locally. The embedded public key proves record integrity, not operator identity or an external trust anchor. No NIST/IEEE compliance is claimed. Keep an external audit export to detect replacement/deletion of the entire local history.

RRS = `(matched unique known blocks + matched known filenames) / (unique known blocks + known filenames)`. The fingerprint search is aligned to 4 KiB boundaries. A zero score is bounded by that known reference set. Complete zero read-back remains an additional, mandatory gate for every certificate.

Images, keys, records and scan results are stored locally in IndexedDB. No image bytes are uploaded. Clearing site/browser data removes the workspace. Google Fonts requests contain no image data; system fonts work as fallback.

## Structure

```text
dist/
  index.html       application shell
  styles.css       responsive visual system
  app.js           views, operations, dialogs and downloads
  core.js          fixtures, carving, fingerprints and verification
  worker.js        bounded image operations off the main thread
  integrity.js     record signing/verification and audit verification
  storage.js       transactional IndexedDB persistence
tests/
  engine.test.js   positive, negative, residue and tamper tests
server.mjs         dependency-free localhost preview
```

## Next implementation boundary

The proposal’s physical-media workflow needs a separately authenticated Linux agent, a narrowly scoped privileged execution boundary, system-disk exclusion, device identity confirmation, persistent job recovery and independent forensic-tool results. Media probing, filesystem residue cleanup, ATA/NVMe sanitization, Ed25519 operator identities and independent-tool attestations are future work, not hidden behind simulated dashboard states.

## Validation

`npm test` covers valid/decodeable fixtures, initial recoverability, complete erasure, deliberately skipped metadata cleanup, relocated known blocks, unknown-image scores, one-byte residue, malformed/truncated carving inputs, signature tampering and audit-chain changes. Browser QA additionally covers recovery downloads, record export/reimport, post-wipe scanning, persistence after reload, imports and responsive navigation.

#!/usr/bin/env python3
"""Independently regenerate SDK-only canonical/signature fixtures with public test keys."""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def digest(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def identity_link(data):
    link = data['link']
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = key.public_key().public_bytes_raw()
    link['mls_epoch'] = str(link['mls_epoch'])
    link['response_signing_public_key_base64url'] = b64(public)
    link['response_signing_public_key_digest'] = digest(public)
    unsigned = copy.deepcopy(link)
    for member in ('payload_digest', 'signature'):
        unsigned['proof'].pop(member, None)
    signing = b'ak.identity_link.v1\n' + canonical(unsigned)
    link['proof']['payload_digest'] = digest(signing)
    link['proof']['signature'] = b64(key.sign(signing))
    data.update(preimage_utf8=signing.decode(), digest=digest(signing), public_test_seed_hex=bytes(range(32)).hex())
    return data


def authority(data):
    keys = [Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32) for n in (1, 2)]
    commit, handoff = data['commit'], data['handoff']
    commit['governance_generation'] = str(commit['governance_generation'])
    commit_core = {k: v for k, v in commit.items() if k not in ('commit_id', 'signature')}
    commit['commit_id'] = 'ak:realm_commit:' + b64(b'\x01' + hashlib.sha256(canonical(commit_core)).digest())
    handoff['change_commit_id'] = commit['commit_id']
    for member in ('from_generation', 'to_generation'):
        handoff[member] = str(handoff[member])
    proof_members = ('old_authority_signature', 'new_authority_acceptance_signature')
    core = {k: v for k, v in handoff.items() if k not in ('handoff_id', *proof_members)}
    handoff['handoff_id'] = 'ak:realm_authority_handoff:' + b64(b'\x01' + hashlib.sha256(canonical(core)).digest())
    for body, members, selected_keys, transcripts in (
        (commit, ('signature',), keys[:1], ('commit_signing_b64',)),
        (handoff, proof_members, keys, ('handoff_old_signing_b64', 'handoff_new_signing_b64')),
    ):
        unsigned = {k: v for k, v in body.items() if k not in members}
        for member, key, transcript in zip(members, selected_keys, transcripts):
            proof = body[member]
            proof.pop('sig', None)
            proof['signed_digest'] = digest(canonical(unsigned))
            binding = {k: v for k, v in proof.items() if k != 'signature'}
            signing = proof['context'].encode() + b'\n' + canonical(binding)
            proof['signature'] = b64(key.sign(signing))
            data[transcript] = b64(signing)
    data['commit_canonical_b64'] = b64(canonical(commit))
    data['handoff_canonical_b64'] = b64(canonical(handoff))
    for name, key in zip(('old', 'new'), keys):
        data[name + '_public_key_b64'] = b64(key.public_key().public_bytes_raw())
    data['public_test_seed_hex'] = {'old': '01' * 32, 'new': '02' * 32}
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    for relative, build in (
        ('crates/models-collaboration/tests/fixtures/identity-link-kat.json', identity_link),
        ('crates/test-kit/fixtures/authority-object-canonical.json', authority),
    ):
        path = ROOT / relative
        rendered = json.dumps(build(json.loads(path.read_text(encoding='utf-8'))), ensure_ascii=False, indent=2) + '\n'
        if args.check:
            if path.read_text(encoding='utf-8') != rendered:
                raise SystemExit('independent wire KAT drift: ' + relative)
        else:
            path.write_text(rendered, encoding='utf-8', newline='\n')
        print(relative + ': exact')


if __name__ == '__main__':
    main()

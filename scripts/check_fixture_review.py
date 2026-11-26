#!/usr/bin/env python3
"""Real offline reviewer/SSHSIG campaign. Keys exist only in disposable synthetic fixtures."""
from __future__ import annotations
import argparse,hashlib,json,os,pathlib,subprocess,tempfile
ROOT=pathlib.Path(__file__).resolve().parent.parent
BIN=ROOT/'target/debug/rustiron-review'
KEYGEN='/usr/bin/ssh-keygen'
ENV={'PATH':'/usr/bin:/bin','SSH_AUTH_SOCK':'/nonexistent/SYNTHETIC_AGENT_CANARY'}

def execute(command,**kwargs):
    return subprocess.run([str(x) for x in command],env=ENV,capture_output=True,timeout=15,**kwargs)

def main():
    global BIN
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--no-build',action='store_true');parser.add_argument('--evidence-dir',type=pathlib.Path);parser.add_argument('--binary',type=pathlib.Path);args=parser.parse_args()
    if args.binary:BIN=args.binary
    if not args.no_build:
        subprocess.run(['cargo','build','--locked','--workspace','--bins'],cwd=ROOT,stdout=subprocess.DEVNULL,check=True)
    cases=[]
    with tempfile.TemporaryDirectory(prefix='ri-synthetic-sshsig-') as temp:
        d=pathlib.Path(temp);plan=json.loads((ROOT/'crates/contracts/tests/fixtures/fixture-plan.json').read_text());grant=json.loads((ROOT/'crates/contracts/tests/fixtures/fixture-grant.json').read_text())
        policy={key:grant[key] for key in ('host_id','host_epoch','profile_digest','requester','issuer','signer_policy_epoch')};policy.update(schema_version=1,verifier_sha256=hashlib.sha256(pathlib.Path(KEYGEN).read_bytes()).hexdigest())
        def write(name,value):
            p=d/name;p.write_text(json.dumps(value) if not isinstance(value,str) else value);return p
        before_scratch=set(pathlib.Path('/tmp').glob('rustiron-review-*'))
        p=write('plan.json',plan);g=write('grant.json',grant);pol=write('policy.json',policy);rev=write('revoked','')
        for name in ['key','wrong-key']:
            result=execute([KEYGEN,'-q','-t','ed25519','-N','','-C','SYNTHETIC_ONLY','-f',d/name]);assert result.returncode==0,result.stderr
        pub=' '.join((d/'key.pub').read_text().split()[:2]);allowed=write('allowed',f'operator_1 namespaces="rustiron-plan-v1" {pub}\n')
        base=[BIN,'--plan',p,'--grant',g,'--policy',pol,'--synthetic-time','1200']
        def review(*extra,code=0,command=None):
            run=execute([*(base if command is None else command),*extra]);assert run.returncode==code,(run.returncode,code,run.stdout,run.stderr)
            assert run.stderr==b'',run.stderr
            assert b'INPUT_CANARY' not in run.stdout or code==0
            return run.stdout
        unsigned=json.loads(review('--output','json'));assert unsigned['signature_status']=='not_checked' and unsigned['execution_authority'] is False
        assert unsigned['plan']==plan and unsigned['grant']==grant and unsigned['synthetic_time'] is True
        payload=review('--output','grant-bytes');assert not payload.endswith(b'\n')
        assert hashlib.sha256(payload).hexdigest()==unsigned['canonical_grant_sha256']
        message=d/'message';message.write_bytes(payload)
        def sign(key='key',namespace='rustiron-plan-v1',source=message):
            sig=pathlib.Path(str(source)+'.sig')
            if sig.exists():sig.unlink()
            run=execute([KEYGEN,'-q','-Y','sign','-f',d/key,'-n',namespace,source]);assert run.returncode==0,run.stderr
            return sig
        sig=sign();verification=['--signature',sig,'--allowed-signers',allowed,'--revocations',rev]
        verified=json.loads(review(*verification,'--output','json'));assert verified['signature_status']=='verified' and verified['execution_authority'] is False
        assert verified['plan']==plan and verified['grant']==grant
        cases+=['unsigned_complete_review_and_exact_grant_export','real_canonical_signature_and_binding_verified']
        human=review(*verification);assert b'"compensation"' in human and b'"limitations"' in human and b'"downtime_estimate"' in human
        cases.append('human_review_shows_complete_semantics')
        if args.evidence_dir:
            args.evidence_dir.mkdir(parents=True,exist_ok=True)
            (args.evidence_dir/'sample-review.json').write_text(json.dumps(verified,indent=2)+'\n')
            (args.evidence_dir/'sample-review.txt').write_bytes(human)
        # Formatting changes in transport do not change the semantic signature payload.
        g.write_text(json.dumps(grant,indent=4)+'\n');review(*verification);cases.append('noncanonical_transport_reuses_identical_signed_payload')
        changed=dict(grant,nonce='another_nonce');g.write_text(json.dumps(changed));review(*verification,code=3);g.write_text(json.dumps(grant));cases.append('changed_signed_nonce_denied')
        sign('wrong-key');review(*verification,code=3);cases.append('wrong_signing_key_denied')
        sign(namespace='other-namespace');review(*verification,code=3);cases.append('wrong_namespace_denied')
        sign();rev.write_text(pub+'\n');review(*verification,code=3);rev.write_text('');cases.append('revoked_key_denied')
        allowed.write_text(f'other_operator namespaces="rustiron-plan-v1" {pub}\n');review(*verification,code=2);cases.append('wrong_allowlisted_principal_denied')
        allowed.write_text(f'* namespaces="rustiron-plan-v1" {pub}\n');review(*verification,code=2);cases.append('wildcard_principal_denied')
        allowed.write_text(f'operator_1 namespaces="rustiron-plan-v1" {pub}\n')
        wrong=dict(policy,host_epoch='other_epoch');pol.write_text(json.dumps(wrong));review(*verification,code=4);pol.write_text(json.dumps(policy));cases.append('independent_epoch_mismatch_denied')
        wrong=dict(policy,verifier_sha256='0'*64);pol.write_text(json.dumps(wrong));review(*verification,code=7);pol.write_text(json.dumps(policy));cases.append('unreviewed_binary_hash_denied')
        review(*verification,code=3,command=[*base[:-1],'1900']);cases.append('expiry_denied_before_verification')
        rev.unlink();review(*verification,code=2);rev.write_text('');cases.append('missing_revocation_policy_denied')
        g.write_text(json.dumps(grant,indent=2));pretty_sig=sign(source=g);review('--signature',pretty_sig,'--allowed-signers',allowed,'--revocations',rev,code=3);cases.append('signature_over_pretty_transport_denied')
        sign();sig.write_text('INPUT_CANARY invalid signature');review(*verification,code=3);cases.append('signature_error_is_redacted')
        sign();p.unlink();p.symlink_to(ROOT/'crates/contracts/tests/fixtures/fixture-plan.json');review(*verification,code=2);p.unlink();p.write_text(json.dumps(plan));cases.append('symlink_input_denied')
        fifo=d/'fifo';os.mkfifo(fifo);review(code=2,command=[*base[:2],fifo,*base[3:]]);cases.append('special_file_is_nonblocking_and_denied')
        review('--signature',sig,code=2);cases.append('partial_signature_arguments_denied')
        bad=execute([BIN,'--INPUT_CANARY']);assert bad.returncode==2 and b'INPUT_CANARY' not in bad.stdout+bad.stderr;cases.append('usage_error_is_redacted')
        # ASCII property keys and exact integers make this a simple independent fixture oracle.
        malicious=json.loads(json.dumps(plan));malicious['limitations'][0]='Escaped text \u202e\x1b[31m'
        canonical=json.dumps(malicious,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        malicious_grant=dict(grant,plan_digest=hashlib.sha256(b'rustiron/plan/v1\0'+canonical).hexdigest())
        p.write_text(json.dumps(malicious));g.write_text(json.dumps(malicious_grant));safe=review()
        assert '\u202e'.encode() not in safe and b'\x1b' not in safe and b'\\u{202e}' in safe
        cases.append('human_bidi_and_terminal_controls_escaped')
        assert set(pathlib.Path('/tmp').glob('rustiron-review-*'))==before_scratch
        cases.append('verification_scratch_cleaned_on_success_and_rejection')
        assert not any((d/name).read_text().startswith('-----BEGIN OPENSSH PRIVATE KEY-----') for name in ['allowed','revoked','plan.json','grant.json','policy.json'])
    print(json.dumps({'task':'S02/W010','status':'passed','cases':cases,'key_custody':'synthetic disposable keys only; no real custody proof','verifier_sha256':policy['verifier_sha256'],'limits':'offline signature and binding only; no replay, root enrollment or execution authority'},indent=2))

if __name__=='__main__':main()

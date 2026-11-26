"""RecoveryReceipt v1 validator: tampering and aggregation are rejected."""
import copy,hashlib,importlib.util,json,pathlib,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('check_receipt',ROOT/'scripts/check_receipt.py')
CHECK=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(CHECK)

def receipt():
    body={"receipt_schema":"rustiron-recovery-receipt/1","site_id":"blog13",
          "fields":{name:{"status":"pass","scope":"lab"} for name in CHECK.FIELDS},
          "attester":{"kind":"local_executor_self_attested","note":"local"},
          "limitations":["lab only"]}
    body["fields"]["independent_copy_confirmed"]={"status":"fail","scope":"local-PC destination"}
    return {"body":body,"body_sha256":hashlib.sha256(CHECK.canonical(body)).hexdigest()}

class ReceiptTests(unittest.TestCase):
    def test_consistent_receipt_passes(self):
        self.assertEqual(CHECK.problems(receipt()),[])

    def test_any_body_change_breaks_the_hash(self):
        changed=receipt();changed["body"]["fields"]["independent_copy_confirmed"]["status"]="pass"
        self.assertIn("body_sha256 does not match the canonical body",CHECK.problems(changed))

    def test_missing_or_aggregated_fields_are_rejected(self):
        missing=receipt();del missing["body"]["fields"]["decryption_tested"]
        missing["body_sha256"]=hashlib.sha256(CHECK.canonical(missing["body"])).hexdigest()
        self.assertIn("the seven fields are not exactly present",CHECK.problems(missing))
        rolled=receipt();rolled["body"]["healthy"]=True
        rolled["body_sha256"]=hashlib.sha256(CHECK.canonical(rolled["body"])).hexdigest()
        self.assertIn("aggregate verdict 'healthy' is not allowed",CHECK.problems(rolled))

    def test_unknown_status_and_unlabelled_attester_are_rejected(self):
        bad=receipt();bad["body"]["fields"]["health_checks_passed"]["status"]="ok"
        bad["body"]["attester"]={"kind":"independent"}
        bad["body_sha256"]=hashlib.sha256(CHECK.canonical(bad["body"])).hexdigest()
        found=CHECK.problems(bad)
        self.assertIn("health_checks_passed: needs an allowed status and a scope",found)
        self.assertIn("attester must be labelled local_executor_self_attested",found)

    def test_optional_spec_keys_are_checked_when_present(self):
        present=receipt()
        for entry in present["body"]["fields"].values():
            entry["observed_at"]=1300
            entry["evidence_refs"]=[]
            entry["limitations"]=["no separate evidence object is stored for this field"]
        present["body_sha256"]=hashlib.sha256(CHECK.canonical(present["body"])).hexdigest()
        self.assertEqual(CHECK.problems(present),[])
        bad=receipt()
        bad["body"]["fields"]["decryption_tested"]["observed_at"]=True
        bad["body"]["fields"]["decryption_tested"]["evidence_refs"]="journal"
        bad["body_sha256"]=hashlib.sha256(CHECK.canonical(bad["body"])).hexdigest()
        found=CHECK.problems(bad)
        self.assertIn("decryption_tested: observed_at must be a non-negative integer",found)
        self.assertIn("decryption_tested: evidence_refs must be an array of non-empty strings",found)

    def test_an_unclaimed_snapshot_needs_a_failed_capture_without_a_snapshot(self):
        def settled(state="failed",snapshot=None,unclaimed=None):
            body=receipt()["body"]
            body["operation"]={"verb":"backup_capture","state":state}
            body["snapshot_id"]=snapshot
            body["unclaimed_snapshot"]=unclaimed or {"snapshot_id":"a5"*32,"claimed":False,"scope":"evidence only"}
            return {"body":body,"body_sha256":hashlib.sha256(CHECK.canonical(body)).hexdigest()}
        self.assertEqual(CHECK.problems(settled()),[])
        for bad in (settled(state="succeeded"),settled(snapshot="a5"*32),
                    settled(unclaimed={"snapshot_id":"A5"*32,"claimed":False,"scope":"x"}),
                    settled(unclaimed={"snapshot_id":"a5"*32,"claimed":True,"scope":"x"}),
                    settled(unclaimed={"snapshot_id":"a5"*32,"claimed":False})):
            self.assertIn("unclaimed_snapshot needs a failed capture without a snapshot, a 64 lowercase hex id, claimed false and a scope",CHECK.problems(bad))

    def test_a_refused_probe_needs_stated_fields_and_limitations(self):
        # W374: the W371 export of a refused probe (null fields and limitations) is refused; the fixed export passes.
        sealed=json.loads((ROOT/"docs/validation/S10-W371/receipt-op_w371_probe_1.json").read_text())
        found=CHECK.problems(sealed)
        self.assertIn("the seven fields are not exactly present",found)
        self.assertIn("limitations must be stated",found)
        body=copy.deepcopy(sealed["body"])
        scope="not attempted: the probe was refused with NOT_ADMITTED_FOR_EFFECT before any sandbox or snapshot restore"
        body["fields"]={name:{"status":"not_run","scope":scope,"observed_at":1794551439,"evidence_refs":[],
                              "limitations":["no separate evidence object is stored for this field"]} for name in CHECK.FIELDS}
        body["limitations"]=["derived at export from the probe journal row; the stored probe receipt states no limitations",
                             "the probe was refused with NOT_ADMITTED_FOR_EFFECT before any sandbox; snapshot restore and decryption, restic check, isolated restore, database import, and application health were not attempted; a repository identity check can have run before the refusal",
                             "no field claims a result that the stored probe receipt did not record"]
        fixed={"body":body,"body_sha256":hashlib.sha256(CHECK.canonical(body)).hexdigest()}
        self.assertEqual(CHECK.problems(fixed),[])

    def capture(self,state="succeeded",snapshot="a5"*32,retention=None,refusal=None):
        body=receipt()["body"]
        body["operation"]={"verb":"backup_capture","state":state,"started_at":1000}
        body["snapshot_id"]=snapshot
        if retention is not None:body["retention"]=retention
        if refusal is not None:body["refusal"]=refusal
        return {"body":body,"body_sha256":hashlib.sha256(CHECK.canonical(body)).hexdigest()}

    def evidence(self):
        check={"result":"passed","versioning":"Enabled","default_mode":"COMPLIANCE","default_days":30}
        until=1000+30*86400
        return {"days":30,"status":"recorded","checks":{"before":dict(check),"after":dict(check)},
                "objects":[{"kind":"snapshot","object_id":"a5"*32,"version_id":"76b01aea-db7c-4b38-b41d-3c031085d108","mode":"COMPLIANCE","retain_until":until},
                           {"kind":"pack","object_id":"9f"*32,"version_id":"v2","mode":"COMPLIANCE","retain_until":until+5}],
                "scope":"read back by the lock postcheck"}

    def test_recorded_retention_evidence_is_checked(self):
        # W391: per-version evidence must name the snapshot once and cover the days.
        self.assertEqual(CHECK.problems(self.capture(retention=self.evidence())),[])
        self.assertEqual(CHECK.problems(self.capture(retention={"days":30,"status":"not_recorded"})),[])
        message="retention evidence needs a succeeded capture, passed before and after checks, and one COMPLIANCE version per object that names the snapshot once and covers the days"
        def bad(change,**kw):
            evidence=self.evidence();change(evidence)
            self.assertIn(message,CHECK.problems(self.capture(retention=evidence,**kw)))
        bad(lambda e:None,state="failed",snapshot=None)
        bad(lambda e:e["objects"][0].update(object_id="9f"*32))
        bad(lambda e:e["objects"].pop(0))
        bad(lambda e:e["objects"].clear())
        bad(lambda e:e["objects"][1].update(version_id="null"))
        bad(lambda e:e["objects"][1].update(version_id="has space"))
        bad(lambda e:e["objects"][1].update(mode="GOVERNANCE"))
        bad(lambda e:e["objects"][1].update(retain_until=1000+29*86400))
        bad(lambda e:e["objects"][1].update(kind="config"))
        bad(lambda e:e["objects"].append(dict(e["objects"][1])))
        bad(lambda e:e["checks"]["after"].update(result="refused"))
        bad(lambda e:e["checks"]["before"].update(default_days=29))
        bad(lambda e:e.pop("checks"))
        bad(lambda e:e.update(status="verified"))
        bad(lambda e:e.update(days=True))

    def test_a_refusal_code_needs_a_failed_capture_without_a_snapshot(self):
        self.assertEqual(CHECK.problems(self.capture(state="failed",snapshot=None,refusal="RETENTION_LOCK_UNVERIFIED")),[])
        message="refusal needs a failed capture without a snapshot and a code of 1 to 64 characters A-Z, 0-9 and _"
        for kw in ({"refusal":"STEP_FAILED"},{"state":"failed","snapshot":None,"refusal":"lower"},
                   {"state":"failed","snapshot":None,"refusal":"A"*65},{"state":"failed","snapshot":None,"refusal":""},
                   {"state":"failed","snapshot":None,"refusal":7}):
            self.assertIn(message,CHECK.problems(self.capture(**kw)),kw)

    def test_old_sealed_capture_receipts_still_pass(self):
        # W391 keeps old rows byte-stable: the W371 product capture states not_recorded.
        sealed=json.loads((ROOT/"docs/validation/S10-W371/receipt-op_w371_cap_1.json").read_text())
        self.assertEqual(sealed["body"]["retention"]["status"],"not_recorded")
        self.assertEqual(CHECK.problems(sealed),[])


VECTORS=json.loads((ROOT/"crates/contracts/tests/fixtures/receipt-signature-vectors.json").read_text())


def signed(vector=None):
    """W392: a receipt from the independent vectors, signed by the RFC 8032 test key."""
    vector=vector or VECTORS["vectors"][0]
    return {"body":json.loads(vector["body_input"]),"body_sha256":vector["body_sha256"],
            "attestation":"self-attested, signed",
            "signature":{"format":"sshsig","namespace":"rustiron-receipt-v1",
                         "key_fingerprint":VECTORS["test_key"]["fingerprint"],"armored":vector["armored"]}}


class SignatureTests(unittest.TestCase):
    """W392 (D-040 item 6): host receipt key signatures, verified with ssh-keygen."""
    key=VECTORS["test_key"]["public_key"]

    def test_each_signed_vector_verifies_with_the_recorded_key(self):
        for vector in VECTORS["vectors"]:
            document=signed(vector)
            self.assertEqual(CHECK.problems(document),[],vector["name"])
            self.assertEqual(CHECK.signature_problems(document,self.key),[],vector["name"])
            self.assertEqual(CHECK.attestation(document),"self-attested, signed")

    def test_a_tampered_body_with_a_matching_digest_is_refused(self):
        document=signed()
        document["body"]["fields"]["independent_copy_confirmed"]["status"]="pass"
        document["body_sha256"]=hashlib.sha256(CHECK.canonical(document["body"])).hexdigest()
        self.assertEqual(CHECK.problems(document),[])
        self.assertIn("signature does not verify with the given public key in namespace rustiron-receipt-v1",
                      CHECK.signature_problems(document,self.key))

    def test_a_wrong_key_is_refused(self):
        found=CHECK.signature_problems(signed(),VECTORS["other_key"]["public_key"])
        self.assertIn("signature does not verify with the given public key in namespace rustiron-receipt-v1",found)
        self.assertIn("key_fingerprint does not match the given public key",found)

    def test_a_signature_in_another_namespace_is_refused(self):
        document=signed()
        document["signature"]["armored"]=VECTORS["wrong_namespace"]["armored"]
        self.assertIn("signature does not verify with the given public key in namespace rustiron-receipt-v1",
                      CHECK.signature_problems(document,self.key))
        relabelled=signed();relabelled["signature"]["namespace"]="rustiron-plan-v1"
        self.assertIn("signature namespace must be rustiron-receipt-v1",CHECK.problems(relabelled))

    def test_a_missing_signature_is_refused_when_a_key_is_given(self):
        unsigned=signed();del unsigned["signature"];unsigned["attestation"]="self-attested, unsigned"
        self.assertEqual(CHECK.problems(unsigned),[])
        self.assertEqual(CHECK.attestation(unsigned),"self-attested, unsigned")
        self.assertIn("a signature is required with --public-key, and the receipt has none",
                      CHECK.signature_problems(unsigned,self.key))
        old=json.loads((ROOT/"docs/validation/S10-W041/receipt-op_pr13.json").read_text())
        self.assertEqual(CHECK.problems(old),[])
        self.assertEqual(CHECK.attestation(old),"self-attested, unsigned")
        self.assertIn("a signature is required with --public-key, and the receipt has none",
                      CHECK.signature_problems(old,self.key))

    def test_the_label_must_agree_with_the_signature(self):
        stripped=signed();del stripped["signature"]
        self.assertIn("attestation 'self-attested, signed' needs a signature",CHECK.problems(stripped))
        claimed=signed();claimed["attestation"]="self-attested, unsigned"
        self.assertIn("a signature needs the attestation 'self-attested, signed'",CHECK.problems(claimed))
        other=signed();other["attestation"]="independently attested"
        self.assertIn("unknown attestation 'independently attested'",CHECK.problems(other))
        extra=signed();extra["signature"]["key_path"]="/etc/rustiron/receipt-key/ed25519"
        self.assertIn("signature has unknown members: key_path",CHECK.problems(extra))

    def test_the_command_line_verifies_with_a_public_key_file(self):
        import subprocess,tempfile
        with tempfile.TemporaryDirectory() as folder:
            folder=pathlib.Path(folder)
            (folder/"receipt.json").write_text(json.dumps(signed()))
            (folder/"key.pub").write_text(self.key+" host-receipt\n")
            (folder/"other.pub").write_text(VECTORS["other_key"]["public_key"]+"\n")
            def run(*arguments):
                return subprocess.run([sys.executable,"-I",str(ROOT/"scripts/check_receipt.py"),*arguments],
                                      capture_output=True,text=True)
            good=run(str(folder/"receipt.json"),"--public-key",str(folder/"key.pub"))
            self.assertEqual(good.returncode,0,good.stdout+good.stderr)
            self.assertIn("PASS: consistent self-attested, signed receipt; signature verified with "
                          +VECTORS["test_key"]["fingerprint"],good.stdout)
            bad=run(str(folder/"receipt.json"),"--public-key",str(folder/"other.pub"))
            self.assertEqual(bad.returncode,1)
            self.assertIn("FAIL: signature does not verify",bad.stdout)
            plain=run(str(folder/"receipt.json"))
            self.assertEqual(plain.returncode,0)
            self.assertIn("signature present, not verified: no --public-key given",plain.stdout)


if __name__=="__main__":unittest.main()

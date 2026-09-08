"""Full test suite for the JUMPPER reference implementation.

Every assertion is executable. Nothing is asserted that is not measured. The gas
model is validated against a real Ethereum mainnet transaction, not against a
specification read optimistically.
"""

import hashlib, json, os, unittest
from jumpper import anchor as AN, batch as BA, canonical as CAN, claim as CL, merkle as MK

HERE = os.path.dirname(os.path.abspath(__file__))
REAL_CALLDATA = ('{"protocol":"saos-dex/v1","action":"chain-seal","at":"2026-09-08T02:30:53.712Z",'
                 '"height":108,"stateRoot":"6d4c4a120df44afb530180f78688cc15fffa66688e20ef80675710fad8f30843",'
                 '"digest":"63b9f46d6269a3ac6921be2162271235500eba40da203dd81d25d1f8e6109213"}')
REAL_GAS_USED = 30920
REAL_GAS_PRICE = 1050884809

def lh(s): return hashlib.sha256(s.encode()).hexdigest()

class TestCanonical(unittest.TestCase):
    def test_key_order_independent(self): self.assertEqual(CAN.canonical({"b":1,"a":2}), '{"a":2,"b":1}')
    def test_nested_sorted(self): self.assertEqual(CAN.canonical({"o":{"z":1,"a":2}}), '{"o":{"a":2,"z":1}}')
    def test_negative_zero_normalized(self): self.assertEqual(CAN.canonical({"x":-0.0}), '{"x":0}')
    def test_integral_float_becomes_int(self): self.assertEqual(CAN.canonical({"x":1.0}), '{"x":1}')
    def test_non_finite_rejected(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(CAN.CanonicalizationError): CAN.canonical({"x": bad})
    def test_no_insignificant_whitespace(self): self.assertNotIn(" ", CAN.canonical({"a":[1,2],"b":{"c":3}}))

class TestMerkle(unittest.TestCase):
    def test_every_leaf_proves_at_many_sizes(self):
        for n in (1,2,3,4,5,7,8,9,16,17,33,100):
            lv=[lh("leaf-%d-%d"%(n,i)) for i in range(n)]; rt=MK.root(lv)
            for i,leaf in enumerate(lv): self.assertTrue(MK.verify(leaf,MK.proof(lv,i),rt),"n=%d i=%d"%(n,i))
    def test_odd_node_duplicated_not_self_hashed(self):
        lv=[lh("leaf-5-%d"%i) for i in range(5)]; self.assertEqual(MK.build(lv)[1][-1], lv[-1])
    def test_single_leaf_root_is_leaf(self): self.assertEqual(MK.root([lh("only")]), lh("only"))
    def test_tampered_leaf_rejected(self):
        lv=[lh("leaf-5-%d"%i) for i in range(5)]; self.assertFalse(MK.verify(lh("evil"),MK.proof(lv,0),MK.root(lv)))
    def test_proof_from_other_tree_rejected(self):
        lv=[lh("leaf-5-%d"%i) for i in range(5)]; self.assertFalse(MK.verify(lv[0],MK.proof(lv,0),MK.root(lv[:4])))
    def test_order_sensitive(self):
        a=[lh("x"),lh("y")]; self.assertNotEqual(MK.root(a), MK.root(list(reversed(a))))
    def test_empty_rejected(self):
        with self.assertRaises(ValueError): MK.root([])
    def test_bad_leaf_length_rejected(self):
        with self.assertRaises(ValueError): MK.root(["abc"])

class TestClaim(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(CL.make_claim({"a":1},"2026-09-08T00:00:00Z").leaf_hash,
                         CL.make_claim({"a":1},"2026-09-08T00:00:00Z").leaf_hash)
    def test_payload_key_order_irrelevant(self):
        self.assertEqual(CL.make_claim({"a":1,"b":2},"2026-09-08T00:00:00Z").leaf_hash,
                         CL.make_claim({"b":2,"a":1},"2026-09-08T00:00:00Z").leaf_hash)
    def test_timestamp_changes_hash(self):
        self.assertNotEqual(CL.make_claim({"a":1},"2026-09-08T00:00:00Z").leaf_hash,
                            CL.make_claim({"a":1},"2026-09-08T00:00:01Z").leaf_hash)
    def test_private_hides_payload_but_reports_size(self):
        c=CL.make_claim({"secret":"value"},"2026-09-08T00:00:00Z",public=False)
        self.assertEqual(c.canonical_payload,""); self.assertGreater(c.payload_size,0)
        self.assertNotIn("value", json.dumps(c.disclosure()))
    def test_public_keeps_payload(self):
        self.assertEqual(CL.make_claim({"a":1},"2026-09-08T00:00:00Z",public=True).canonical_payload,'{"a":1}')
    def test_bad_timestamp_rejected(self):
        for bad in ("nope","2026-09-08","2026-09-08T00:00:00",""):
            with self.assertRaises(CL.ClaimError): CL.make_claim({"a":1},bad)

class TestAnchorGasModel(unittest.TestCase):
    def test_exact_match_real_mainnet_gas(self):
        self.assertEqual(AN.estimate_cost(REAL_CALLDATA.encode(),REAL_GAS_PRICE).total_gas, REAL_GAS_USED)
    def test_exact_match_real_mainnet_cost_wei(self):
        self.assertEqual(AN.estimate_cost(REAL_CALLDATA.encode(),REAL_GAS_PRICE).cost_wei, REAL_GAS_USED*REAL_GAS_PRICE)
    def test_eip7623_floor_binds_for_ascii(self):
        c=AN.estimate_cost(REAL_CALLDATA.encode(),REAL_GAS_PRICE)
        self.assertEqual((c.binding_rule,c.tokens,c.gas_floor,c.gas_eip2028),("EIP-7623-floor",992,9920,3968))
    def test_naive_eip2028_model_would_underestimate(self):
        c=AN.estimate_cost(REAL_CALLDATA.encode(),REAL_GAS_PRICE)
        self.assertEqual(21000+c.gas_eip2028, 24968); self.assertEqual(REAL_GAS_USED-24968, 5952)
    def test_zero_bytes_cheaper(self):
        self.assertLess(AN.total_gas(b"\x00"*100), AN.total_gas(b"\x01"*100))

class TestAnchorPayload(unittest.TestCase):
    def test_roundtrip(self):
        d=AN.decode_calldata(AN.to_calldata_hex(AN.build_payload(1,"ab"*32,1000,"2026-09-08T00:00:00Z")))
        self.assertEqual((d["root"],d["height"],d["leafCount"],d["protocol"]),("ab"*32,1,1000,AN.PROTOCOL))
    def test_verify_match_and_reject(self):
        hx=AN.to_calldata_hex(AN.build_payload(7,"cd"*32,42,"2026-09-08T00:00:00Z"))
        self.assertTrue(AN.verify_anchor_matches(hx,7,"cd"*32,42))
        self.assertFalse(AN.verify_anchor_matches(hx,8,"cd"*32,42))
        self.assertFalse(AN.verify_anchor_matches(hx,7,"ab"*32,42))
        self.assertFalse(AN.verify_anchor_matches(hx,7,"cd"*32,43))
    def test_witness_embedded(self):
        w={"steem":1,"hive":2,"tron":3,"ethereum":4,"solana":None}
        p=AN.build_payload(1,"ab"*32,5,"2026-09-08T00:00:00Z",w)
        self.assertEqual(AN.decode_calldata(AN.to_calldata_hex(p))["witness"], w)
    def test_invalid_inputs_rejected(self):
        for args in [(0,"ab"*32,1,"t"),(1,"ZZ"*32,1,"t"),(1,"ab"*32,0,"t")]:
            with self.assertRaises(AN.AnchorError): AN.build_payload(*args)
        with self.assertRaises(AN.AnchorError): AN.decode_calldata("0xzz")

class TestBatchEconomics(unittest.TestCase):
    def test_gas_near_flat_across_six_orders_of_magnitude(self):
        g1=AN.total_gas(AN.payload_bytes(AN.build_payload(1,"ab"*32,1,"2026-09-08T00:00:00Z")))
        g2=AN.total_gas(AN.payload_bytes(AN.build_payload(1,"ab"*32,1000000,"2026-09-08T00:00:00Z")))
        self.assertLess(g2-g1,500); self.assertLess((g2-g1)/g1,0.02)
    def test_root_size_constant(self):
        for n in (1,1000,10000): self.assertEqual(len(MK.root([lh("l%d"%i) for i in range(n)])),64)
    def test_per_claim_cost_falls_with_batch(self):
        g=AN.total_gas(AN.payload_bytes(AN.build_payload(1,"ab"*32,1000,"2026-09-08T00:00:00Z")))
        per=[g*10**9/n for n in (1,100,1000,10000)]
        self.assertEqual(per,sorted(per,reverse=True)); self.assertLess(per[-1],per[0]/1000)

class TestBatcher(unittest.TestCase):
    def test_seals_on_max_leaves_contiguous(self):
        b=BA.Batcher(max_leaves=4,max_age=300); sealed=[]
        for i in range(9):
            s=b.add(CL.make_claim({"i":i},"2026-09-08T00:00:0%dZ"%i),now=1000.0+i)
            if s: sealed.append(s)
        self.assertEqual([x.height for x in sealed],[1,2]); self.assertEqual(b.open_count,1)
    def test_seals_on_max_age(self):
        b=BA.Batcher(max_leaves=10,max_age=1)
        b.add(CL.make_claim({"x":1},"2026-09-08T00:00:00Z"),now=0.0)
        self.assertIsNone(b.seal_if_due(now=0.5))
        s=b.seal_if_due(now=2.0); self.assertIsNotNone(s); self.assertEqual(s.seal_reason,"max_age")
    def test_force_seal(self):
        b=BA.Batcher(max_leaves=100); b.add(CL.make_claim({"x":1},"2026-09-08T00:00:00Z"),now=0.0)
        s=b.force_seal(now=1.0); self.assertEqual((s.height,s.seal_reason),(1,"forced"))
    def test_invariants_hold_after_many_batches(self):
        b=BA.Batcher(max_leaves=3,max_age=300)
        for i in range(20): b.add(CL.make_claim({"i":i},"2026-09-08T00:00:%02dZ"%i),now=float(i))
        b.force_seal(now=100.0); b.assert_consistent()
        self.assertEqual([x.height for x in b.sealed],list(range(1,len(b.sealed)+1)))
    def test_all_proofs_valid_in_sealed_batch(self):
        b=BA.Batcher(max_leaves=5)
        for i in range(5): b.add(CL.make_claim({"i":i},"2026-09-08T00:00:0%dZ"%i),now=float(i))
        s=b.sealed[0]
        for leaf in s.leaf_hashes: self.assertTrue(MK.verify(leaf,s.proofs[leaf],s.root))

class TestGoldenVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p=os.path.join(HERE,"golden_vectors.json")
        if not os.path.exists(p): raise unittest.SkipTest("golden_vectors.json not present")
        cls.v=json.load(open(p))
    def test_canonical_vectors(self):
        for c in self.v["canonicalization"]: self.assertEqual(CAN.canonical(c["input"]),c["output"])
    def test_merkle_root_vector(self): self.assertEqual(MK.root(self.v["merkle"]["leaves"]),self.v["merkle"]["root"])
    def test_merkle_proof_vectors(self):
        rt=self.v["merkle"]["root"]
        for c in self.v["merkle"]["proofs"]: self.assertTrue(MK.verify(self.v["merkle"]["leaves"][c["index"]],c["path"],rt))
    def test_claim_vectors(self):
        for c in self.v["claim"]["cases"]: self.assertEqual(CL.leaf_hash(c["payload"],c["timestamp"]),c["leafHash"])
    def test_anchor_gas_vector_matches_mainnet(self):
        mv=self.v["anchor"]["mainnetValidation"]; self.assertTrue(mv["match"])
        self.assertEqual(mv["modelGasUsed"],mv["actualGasUsed"])
        self.assertEqual(AN.estimate_cost(REAL_CALLDATA.encode(),mv["gasPriceWei"]).total_gas,mv["modelGasUsed"])
    def test_anchor_payload_vector(self):
        pc=self.v["anchor"]["payloadCase"]
        self.assertEqual(AN.build_payload(pc["height"],pc["root"],pc["leafCount"],pc["at"]),pc["payload"])
        self.assertEqual(AN.to_calldata_hex(pc["payload"]),pc["calldataHex"])

if __name__ == "__main__":
    unittest.main(verbosity=2)

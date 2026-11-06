import io
import os
import random
import subprocess
import shutil
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sigtool  # noqa: E402


def rnd(n, rng):
    return bytes(rng.getrandbits(8) for _ in range(n))


class SigtoolTest(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(1337)
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "g1"))
        os.makedirs(os.path.join(self.dir, "g2"))

    def tearDown(self):
        shutil.rmtree(self.dir)

    def put(self, group, name, data):
        p = os.path.join(self.dir, group, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def run_tool(self, *extra):
        g1 = sigtool.expand_paths([os.path.join(self.dir, "g1")])
        g2 = sigtool.expand_paths([os.path.join(self.dir, "g2")])
        unpack = 2 if "unpack" in extra else 0
        samples = [sigtool.load_sample(p, unpack) for p in g1]
        sigs, unc = sigtool.generate(samples, g2, unpack_depth=unpack, verbose=False,
                                     require_all="all" in extra,
                                     redundancy=2 if "r2" in extra else 1)
        self.assertEqual(sigtool.verify(sigs, samples, g2, unpack), [])
        return samples, g2, sigs, unc

    def assert_contract(self, samples, g2, sigs, unc):
        """Каждый непокрытый не указан → покрыт; ни одна сигнатура не в G2."""
        for i, s in enumerate(samples):
            if i not in unc:
                self.assertTrue(any(s.contains(sg.data) for sg in sigs), s.path)
        for p in g2:
            with open(p, "rb") as f:
                data = f.read()
            for sg in sigs:
                self.assertNotIn(sg.data, data)

    def test_common_marker_single_signature(self):
        marker = rnd(80, self.rng)
        shared_clean = rnd(500, self.rng)       # есть и в G1, и в G2 → нельзя брать
        for i in range(5):
            self.put("g1", f"m{i}", rnd(3000, self.rng) + marker + shared_clean + rnd(2000, self.rng))
        for i in range(5):
            self.put("g2", f"c{i}", rnd(4000, self.rng) + shared_clean)
        samples, g2, sigs, unc = self.run_tool()
        self.assertEqual(unc, [])
        self.assertEqual(len(sigs), 1)
        self.assertEqual(len(sigs[0].covers), 5)
        # сигнатура начинается в маркере и может «перетечь» в общий блок:
        # marker+shared_clean есть во всех G1 и отсутствует в G2 — это корректно
        self.assertIn(sigs[0].data, marker + shared_clean)
        self.assertNotIn(sigs[0].data, shared_clean)
        self.assertEqual(len(sigs[0].data), 64)     # расширена до max_len
        self.assert_contract(samples, g2, sigs, unc)

    def test_two_subfamilies_need_two_signatures(self):
        ma, mb = rnd(60, self.rng), rnd(60, self.rng)
        for i in range(3):
            self.put("g1", f"a{i}", rnd(2000, self.rng) + ma + rnd(1000, self.rng))
            self.put("g1", f"b{i}", rnd(2000, self.rng) + mb + rnd(1000, self.rng))
        self.put("g2", "c", rnd(5000, self.rng))
        samples, g2, sigs, unc = self.run_tool()
        self.assertEqual(unc, [])
        self.assertEqual(len(sigs), 2)
        self.assert_contract(samples, g2, sigs, unc)

    def test_require_all_mode(self):
        ma, mb = rnd(60, self.rng), rnd(60, self.rng)
        self.put("g1", "a", rnd(2000, self.rng) + ma)
        self.put("g1", "b", rnd(2000, self.rng) + mb)
        samples, g2, sigs, unc = self.run_tool("all")
        self.assertEqual(sigs, [])
        self.assertEqual(len(unc), 2)

    def test_file_fully_inside_g2_is_uncovered(self):
        blob = rnd(3000, self.rng)
        self.put("g1", "x", blob)
        self.put("g1", "y", rnd(3000, self.rng))
        self.put("g2", "z", rnd(100, self.rng) + blob + rnd(100, self.rng))
        samples, g2, sigs, unc = self.run_tool()
        self.assertEqual([samples[i].path for i in unc], [os.path.join(self.dir, "g1", "x")])
        self.assert_contract(samples, g2, sigs, unc)

    def test_padding_is_not_a_signature(self):
        for i in range(3):
            self.put("g1", f"m{i}", rnd(1000, self.rng) + b"\x00" * 500 + rnd(1000, self.rng))
        self.put("g2", "c", rnd(3000, self.rng))
        samples, g2, sigs, unc = self.run_tool()
        for sg in sigs:
            self.assertNotEqual(sg.data.strip(b"\x00"), b"")
            self.assertGreaterEqual(len(set(sg.data)), 4)

    def test_redundancy(self):
        m1, m2 = rnd(70, self.rng), rnd(70, self.rng)
        for i in range(4):
            self.put("g1", f"m{i}", rnd(1500, self.rng) + m1 + rnd(1500, self.rng) + m2)
        self.put("g2", "c", rnd(3000, self.rng))
        samples, g2, sigs, unc = self.run_tool("r2")
        self.assertEqual(len(sigs), 2)
        for s in samples:
            self.assertEqual(sum(s.contains(sg.data) for sg in sigs), 2)

    def _apk(self, entries):
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in entries.items():
                z.writestr(name, data)
        return bio.getvalue()

    def test_unpack_apk_finds_payload_in_inner_dex(self):
        payload = rnd(200, self.rng)
        framework = rnd(4000, self.rng)   # «общая библиотека», есть и в чистых APK
        for i in range(3):
            self.put("g1", f"evil{i}.apk", self._apk({
                "classes.dex": framework + rnd(500, self.rng),
                "assets/payload.bin": rnd(300, self.rng) + payload,
            }))
        for i in range(3):
            self.put("g2", f"clean{i}.apk", self._apk({"classes.dex": framework + rnd(500, self.rng)}))
        samples, g2, sigs, unc = self.run_tool("unpack")
        self.assertEqual(unc, [])
        self.assertEqual(len(sigs), 1)
        self.assertIn(sigs[0].data, payload)
        self.assertTrue(all("payload.bin" in loc
                            for s in samples for loc in s.where(sigs[0].data)))

    @unittest.skipUnless(shutil.which("yara"), "yara не установлен")
    def test_cli_yara_output_compiles_and_matches(self):
        marker = rnd(64, self.rng)
        for i in range(3):
            self.put("g1", f"m{i}", rnd(2000, self.rng) + marker)
        self.put("g2", "c", rnd(2000, self.rng))
        rule = os.path.join(self.dir, "r.yar")
        rc = sigtool.main(["--g1", os.path.join(self.dir, "g1"), "--g2", os.path.join(self.dir, "g2"),
                           "-f", "yara", "-o", rule, "-q"])
        self.assertEqual(rc, 0)
        hit = subprocess.run(["yara", "-r", rule, self.dir], capture_output=True, text=True).stdout
        self.assertEqual(hit.count("sigtool_generated"), 3)
        self.assertNotIn("g2", hit)


if __name__ == "__main__":
    unittest.main()

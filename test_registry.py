import json
import unittest
from pathlib import Path
from key_registry import verify_registry, fingerprint_b64, SCHEMA

REPO_DIR = Path(__file__).resolve().parent

class KeyRegistryTests(unittest.TestCase):
    def test_registry_signature_and_schema(self):
        reg_path = REPO_DIR / "public-project-keys.json"
        with reg_path.open(encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data.get("schema"), SCHEMA)
        self.assertIn("root_public_key", data)
        self.assertIn("signature", data)
        # Will raise if signature or schema is invalid
        verify_registry(data)

    def test_project_fingerprints_match(self):
        reg_path = REPO_DIR / "public-project-keys.json"
        with reg_path.open(encoding="utf-8") as f:
            data = json.load(f)
        projects = data.get("projects", {})
        self.assertEqual(len(projects), 19)
        # Spot check specific critical projects
        self.assertEqual(
            fingerprint_b64(projects["project-006"]["public_key"]),
            "e91f92abe2e4ca9d4b65dd6c49e8230ff2d7266c0a6990d91e104628a89b6766"
        )
        self.assertEqual(
            fingerprint_b64(projects["project-012"]["public_key"]),
            "13034f6afa3a1f1d8db6d0cb9c5c83210d8f01a90036308dd8db5813e5e827e4"
        )
        self.assertEqual(
            fingerprint_b64(projects["project-013"]["public_key"]),
            "a3c6dd7cbcca31eb861a8de8dbe13f33fe21e59335c1f31388dbffb44ea1b141"
        )
        self.assertEqual(
            fingerprint_b64(projects["project-014"]["public_key"]),
            "8c7f6e91f092a482d3b250e97b8d5ea4302bc771b101346f8ba2d4ee460c7259"
        )
        self.assertEqual(
            fingerprint_b64(projects["project-018"]["public_key"]),
            "cf748daff8695375496791d67ca963e0add179e5065cbc50295fcce1b51bd6e4"
        )


if __name__ == "__main__":
    unittest.main()

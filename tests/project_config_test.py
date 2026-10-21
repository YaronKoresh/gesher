import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestProjectConfig(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    def block(self, header):
        match = re.search(
            rf"^{re.escape(header)}\s*=\s*\[(.*?)\n\]", self.text, re.S | re.M
        )
        self.assertIsNotNone(match, header)
        return re.findall(r'"([^"]+)"', match.group(1))

    def test_every_runtime_dependency_is_imported_by_the_package(self):
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "src" / "gesher").glob("*.py")
        )
        for requirement in self.block("dependencies"):
            name = re.split(r"[\[<>=!~ ]", requirement, maxsplit=1)[0]
            with self.subTest(dependency=name):
                pattern = rf"^(?:import|from) {re.escape(name)}\b"
                self.assertTrue(re.search(pattern, source, re.M), name)

    def test_dev_extras_include_the_type_stubs_of_typed_imports(self):
        extras = self.text.split("[project.optional-dependencies]", 1)[1]
        dev = re.search(r"dev = \[(.*?)\n\]", extras, re.S)
        self.assertIsNotNone(dev)
        names = re.findall(r'"([^"]+)"', dev.group(1))
        self.assertIn("mypy", names)
        self.assertIn("types-requests", names)

    def test_dev_task_points_at_an_existing_entry_point(self):
        match = re.search(r'^dev = "([^"]+)"', self.text, re.M)
        self.assertIsNotNone(match)
        command = match.group(1)
        self.assertNotIn("uvicorn", command)
        self.assertNotIn(":app", command)
        self.assertIn("gesher", command)


if __name__ == "__main__":
    unittest.main()

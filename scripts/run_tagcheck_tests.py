# (Very) simple test runner for tagcheck rules
#
# Expects rules in *.rules files, and for tests in tests/*.json files in the same directory
# Sample directory structure:
#
# tagcheck/
#   indicators.rules
#   tests/
#     indicators.json
#
# The JSON file should be a list of tests, each test should have the following structure:
# {
#     "name": "test_name",
#     "expects_match": [
#         "rule_name1",
#         "rule_name2"
#     ],
#     "expects_no_match": [
#         "rule_name1",
#         "rule_name2"
#     ],
#     "data": {
#         "al_file_name": "test_file.txt",
#         # If there is a list given, it will be collected as in AL
#         "al_network_static_domain": ["example.com", "example.org"],
#     },
#     "skip": false # If true, the test will be skipped
# }
#
# To run tests:
# python scripts/run_tagcheck_tests.py --rules_dir tagcheck
#
# To test a single file:
# python scripts/run_tagcheck_tests.py --rules_dir tagcheck --file indicators.rules

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path

from termcolor import colored

from assemblyline.odm.models.tagging import Tagging

import yara

RULES_DIR = "tagcheck"
YARA_EXTERNALS = [
    *list(Tagging.flat_fields().keys()),
    "submitter",
    "mime",
    "file_type",
    "tag",
    "file_name",
    "file_size",
]


def externals_to_dict(externals: list[str]) -> dict[str, str | int]:
    int_fields = ["file_size"]
    return {
        f"al_{x.replace('.', '_')}": "" if x not in int_fields else 0 for x in externals
    }


EMPTY_EXTERNALS = externals_to_dict(YARA_EXTERNALS)


@dataclass
class RuleTestResults:
    rules_path: str
    samples_path: str = None
    tests_ok: list[str] = field(default_factory=list)
    tests_fail: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class YARATester:
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.rules_paths = list(Path(rules_dir).glob("**/*.rules"))
        self.results: list[RuleTestResults] = []

    def run(self, single_file: str = None):
        if not single_file:
            for rules_path in self.rules_paths:
                self.results.append(self.test(rules_path))
        else:
            path = Path(single_file)
            if path not in self.rules_paths:
                path = next(p for p in self.rules_paths if p.name == single_file)
            self.results.append(self.test(path))

    def _prepare_data(
        self, data: dict[str, str | list[str] | int]
    ) -> dict[str, str | int]:
        return {k: " | ".join(v) if isinstance(v, list) else v for k, v in data.items()}

    def test(self, rules_path: Path):
        results = RuleTestResults(rules_path=rules_path)
        try:
            print(f"Testing {rules_path}")
            # check if compilable
            rules = yara.compile(filepath=str(rules_path), externals=EMPTY_EXTERNALS)

            # check if tests are present
            samples_path = rules_path.parent / "tests" / f"{rules_path.stem}.json"
            if not samples_path.exists():
                print(f"No tests found for {rules_path}")
                return results

            with open(samples_path, "r", encoding="utf-8") as f:
                tests = json.load(f)

            for test in tests:
                test_name = test["name"]
                try:
                    if test.get("skip", False):
                        continue
                    data = self._prepare_data(test["data"])
                    expected_matches = test.get("expects_match", [])
                    expected_no_matches = test.get("expects_no_match", [])

                    matches = rules.match(
                        data="", externals=data, allow_duplicate_metadata=True
                    )
                    found = set(m.rule for m in matches)
                    for rule in expected_matches:
                        if rule not in found:
                            results.tests_fail.append(
                                f"not matched {colored(rule, 'blue')} in {test_name}"
                            )
                        else:
                            results.tests_ok.append(
                                f"matched {colored(rule, 'blue')} in {test_name}"
                            )
                    for rule in expected_no_matches:
                        if rule in found:
                            results.tests_fail.append(
                                f"matched {colored(rule, 'blue')} in {test_name}"
                            )
                        else:
                            results.tests_ok.append(
                                f"not matched {colored(rule, 'blue')} in {test_name}"
                            )

                except Exception as e:
                    results.errors.append(f"Error in test {test_name}: {e}")

        except Exception as e:
            results.errors.append(e)

        return results

    def print_results(self, skip_ok: bool = False):
        failed_files = 0
        for results in self.results:
            if not results.tests_fail and not results.errors:
                if not skip_ok:
                    print(
                        f"{colored('OK', 'green')}: All tests passed for {results.rules_path}"
                    )
                    for test in results.tests_ok:
                        print(f"   [{colored('O', 'green')}] {test}")
                continue
            failed_files += 1
            print(
                f"{colored('FAIL', 'red', attrs=['bold'])}: Some tests failed for {results.rules_path}"
            )
            for test in results.tests_fail:
                print(f"   [{colored('X', 'red', attrs=['bold'])}] {test}")
            for error in results.errors:
                print(f"   [{colored('E', 'red', attrs=['bold'])}] {error}")

        print(f"Total: {len(self.results)} files, {failed_files} failed")

        return failed_files


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rules_dir", help="Path to rules directory", default=RULES_DIR
    )
    parser.add_argument(
        "--file", required=False, help="Name of the file to test in single mode"
    )
    parser.add_argument(
        "--skip-ok", help="Skip printing tests that passed", action="store_true"
    )
    args = parser.parse_args()

    tester = YARATester(args.rules_dir)
    tester.run(args.file)
    r = tester.print_results(skip_ok=args.skip_ok)
    if r > 0:
        exit(1)

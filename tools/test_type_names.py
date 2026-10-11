import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "type_names", Path(__file__).with_name("lint-type-names.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class TypeNameTests(unittest.TestCase):
    def test_rejects_result_and_other_wrappers(self):
        source = "pub struct KeyResult {} pub enum KeyItem {} pub struct KeyDetails {}"
        self.assertEqual(gate.violations("wire/src/new.rs", source),
                         ["KeyResult", "KeyItem", "KeyDetails"])

    def test_accepts_outcomes_and_domain_nouns(self):
        self.assertEqual(gate.violations("wire/src/new.rs",
                         "pub struct KeyOutcome {} pub struct SigningKey {}"), [])

    def test_exception_is_bound_to_owner(self):
        source = "pub struct IceCandidate {}"
        self.assertEqual(gate.violations("models-collaboration/src/call_signal.rs", source), [])
        self.assertEqual(gate.violations("wire/src/new.rs", source), ["IceCandidate"])

    def test_verified_poll_answer_exception_is_exact(self):
        source = "pub struct VerifiedPollResponse {} pub struct OtherResponse {}"
        self.assertEqual(gate.violations("models-collaboration/src/poll.rs", source),
                         ["OtherResponse"])
        self.assertEqual(gate.violations("wire/src/new.rs", source),
                         ["VerifiedPollResponse", "OtherResponse"])

    def test_comments_strings_and_error_aliases_are_not_dtos(self):
        self.assertEqual(gate.violations("wire/src/new.rs", '''
            // pub struct FakeResult {}
            const EXAMPLE: &str = "pub enum FakeItem {}";
            pub type Result<T> = std::result::Result<T, Error>;
        '''), [])


if __name__ == "__main__":
    unittest.main()

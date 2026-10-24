import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "type_names", Path(__file__).with_name("lint-type-names.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class TypeNameTests(unittest.TestCase):
    def test_row_reexports_cannot_restore_a_retired_public_alias(self):
        self.assertEqual(gate.violations('wire/src/new.rs',
            'pub use domain::ObjectView as ObjectRow; pub use domain::{StateView as StateRow};'),
            ['ObjectRow', 'StateRow'])

    def test_primary_ci_executes_the_type_name_gate_and_mutations(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        self.assertIn('--check sdk.protocol-type-names --check sdk.protocol-type-names-regression', workflow)


    def test_public_row_struct_enum_and_alias_are_rejected(self):
        self.assertEqual(gate.violations('wire/src/new.rs',
            'pub struct ObjectRow {} pub enum StateRow {} pub type AliasRow = ObjectView;'),
            ['ObjectRow', 'StateRow', 'AliasRow'])
        self.assertEqual(gate.violations('wire/src/new.rs',
            'struct StorageRow {} pub struct ObjectView {} pub struct CurrentObject {}'), [])


    def test_body_aliases_must_use_the_canonical_type_directly(self):
        self.assertEqual(gate.violations('wire/src/new.rs',
                         'pub type IssueResponseBody = Receipt; pub type Result<T> = std::result::Result<T, Error>;'),
                         ['IssueResponseBody'])

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
        source = "pub struct VerifiedPollVote {} pub struct OtherResponse {}"
        self.assertEqual(gate.violations("models-collaboration/src/poll.rs", source),
                         ["OtherResponse"])
        self.assertEqual(gate.violations("wire/src/new.rs", source),
                         ["OtherResponse"])

    def test_comments_strings_and_error_aliases_are_not_dtos(self):
        self.assertEqual(gate.violations("wire/src/new.rs", '''
            // pub struct FakeResult {}
            const EXAMPLE: &str = "pub enum FakeItem {}";
            pub type Result<T> = std::result::Result<T, Error>;
        '''), [])


if __name__ == "__main__":
    unittest.main()

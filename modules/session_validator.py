from pathlib import Path
from modules.cron_matcher import CronMatcher
import hashlib
import json
import os

# Constants
PASS_ICON = "✅"
FAIL_ICON = "❌"
UNKNOWN_ICON = "❓"

# Default paths
script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
state_file = script_dir / ".state" / "summaries.json"
expectations_file = "expectations.json"


class SessionValidator:
    """
    Handles validation of iRacing sessions against defined expectations.
    This class is responsible for:
    - Loading and parsing expectations
    - Comparing session data against expectations
    - Tracking changes in sessions over time
    - Formatting validation results
    """

    def __init__(self, expectations_path=expectations_file):
        """
        Initialize the SessionValidator with expectations.

        Args:
            expectations_path: Path to the JSON file containing expectations
        """
        with open(expectations_path, 'r') as f:
            expectations = json.load(f)
        # Replace any 'launch_at' with a matcher callable
        for exp in expectations:
            if 'expectation' in exp and isinstance(exp['expectation'], dict):
                for key, val in exp['expectation'].items():
                    if isinstance(val, dict) and 'cron' in val and 'margin' in val:
                        exp['expectation'][key] = CronMatcher(val['cron'], val['margin'])
        self.expectations = expectations
        self.expectations_path = expectations_path

    def _compare_expectations(self, expected, actual, path=""):
        """
        Recursively compare the expected and actual values.

        Args:
            expected: The expected value or structure
            actual: The actual value or structure
            path: The current path in the structure for reporting

        Returns:
            List of validation results
        """
        results = []
        if isinstance(expected, dict):
            if not isinstance(actual, dict):
                results.append(f"{FAIL_ICON} {path} type mismatch: expected dict, got {type(actual).__name__}")
                return results
            for k, v in expected.items():
                new_path = f"{path}.{k}" if path else k
                if k in actual:
                    results.extend(self._compare_expectations(v, actual[k], new_path))
                else:
                    results.append(f"{UNKNOWN_ICON} {new_path} NOT FOUND")
        elif isinstance(expected, list):
            if not isinstance(actual, list):
                results.append(f"{FAIL_ICON} {path} type mismatch: expected list, got {type(actual).__name__}")
                return results
            for i, v in enumerate(expected):
                if i < len(actual):
                    results.extend(self._compare_expectations(v, actual[i], f"{path}[{i}]"))
                else:
                    results.append(f"{UNKNOWN_ICON} {path}[{i}] NOT FOUND in actual list")
        elif callable(expected):
            ok, msg = expected(actual)
            if ok:
                results.append(f"{PASS_ICON} {path} {msg}")
            else:
                results.append(f"{FAIL_ICON} {path} {msg}")
        else:
            if expected == actual:
                results.append(f"{PASS_ICON} {path} correct: {actual} == {expected}")
            else:
                results.append(f"{FAIL_ICON} {path} INCORRECT: {actual} != {expected}")
        return results

    def validate_session(self, session):
        """
        Validate a single session against expectations.

        Args:
            session: Session data to validate

        Returns:
            Dictionary containing validation results
        """
        # Support single or multiple expectations, each with a name
        expectations = self.expectations
        if not isinstance(expectations, list):
            expectations = [expectations]

        best_result = None
        best_mismatches = None
        best_expectation = None
        best_name = None
        all_expectation_results = {}

        for exp in expectations:
            # Support both legacy (dict) and named (dict with 'name' and 'expectation') formats
            if isinstance(exp, dict) and 'expectation' in exp and 'name' in exp:
                name = exp['name']
                expectation = exp['expectation']
            else:
                name = None
                expectation = exp

            results = self._compare_expectations(expectation, session)
            mismatches = sum(1 for r in results if r.startswith(f"{FAIL_ICON}") or r.startswith(f"{UNKNOWN_ICON}"))

            # Store results for all named expectations
            if name:
                all_expectation_results[name] = results

            # Track the best matching expectation
            if best_mismatches is None or mismatches < best_mismatches:
                best_mismatches = mismatches
                best_result = results
                best_expectation = expectation
                best_name = name

        key = f"{session.get('session_name', '<no name>')} -- {session.get('session_desc', '<no desc>')}"
        header = key

        # Return the best match and results from all expectations
        result = {
            header: best_result,
            'matched_expectation': best_expectation,
            'matched_expectation_name': best_name
        }

        # Only include all_expectation_results if there are mismatches and multiple named expectations
        if best_mismatches > 0 and len(all_expectation_results) > 0:
            result['all_expectation_results'] = all_expectation_results

        return result

    def __call__(self, sessions, summaries_path=state_file, force=False):
        """
        Validate multiple sessions, tracking changes from previous validations.

        Args:
            sessions: List of session data to validate
            summaries_path: Path to the state file
            force: Whether to force validation regardless of changes

        Returns:
            List of validation results for changed sessions
        """
        if not sessions:
            return False

        if os.path.exists(summaries_path):
            with open(summaries_path, 'r') as f:
                prev_summaries = json.load(f)
        else:
            prev_summaries = {}
        new_summaries = {}
        results = []

        # Compute the current expectations revision
        with open(self.expectations_path, 'rb') as f:
            current_revision = hashlib.sha256(f.read()).hexdigest()
        prev_revision = prev_summaries.get('revision')

        # If the revision has changed, force revalidation
        if current_revision != prev_revision:
            force = True

        for session in sessions:
            session_id = str(session.get('launch_at'))
            session_hash = hashlib.sha256(json.dumps(session, sort_keys=True).encode()).hexdigest()
            new_summaries[session_id] = session_hash
            if session_id not in prev_summaries or prev_summaries[session_id] != session_hash or force:
                results.append(self.validate_session(session))

        # Save the new revision and summaries
        new_summaries['revision'] = current_revision

        os.makedirs(os.path.dirname(summaries_path), exist_ok=True)
        with open(summaries_path, 'w') as f:
            json.dump(new_summaries, f, indent=2)

        formatted_results = []
        for result in results:
            # Extract session name and results
            session_name = list(result.keys())[0]
            session_results = result[session_name]

            # Check if there are any failing validations
            validation_failures = [sr for sr in session_results if sr.startswith(f"{FAIL_ICON}") or sr.startswith(f"{UNKNOWN_ICON}")]

            # If no failures, show a success message
            if not validation_failures:
                result_string = f">>> # {session_name}:\n{PASS_ICON} All checks passed!"
                result_string += f"\n ### Matched {result.get('matched_expectation_name', 'None')}"
                formatted_results.append(result_string)
                continue

            # If we have failures and additional expectation results, show all of them
            result_string = f">>> # {session_name}:\n"

            # If there are additional expectations that were checked
            if 'all_expectation_results' in result and result['all_expectation_results']:
                all_exp_results = result['all_expectation_results']

                # Add results for each expectation
                for exp_name, exp_results in all_exp_results.items():
                    exp_failures = [er for er in exp_results if er.startswith(f"{FAIL_ICON}") or er.startswith(f"{UNKNOWN_ICON}")]
                    if exp_failures:
                        result_string += f"\n### Failed Case: {exp_name}\n"
                        result_string += "\n".join(exp_failures)
                        result_string += "\n"
            else:
                # Fall back to just showing the failures from the best match
                result_string += "\n".join(validation_failures)

            formatted_results.append(result_string)

        output = "\n\n".join(formatted_results)
        return output

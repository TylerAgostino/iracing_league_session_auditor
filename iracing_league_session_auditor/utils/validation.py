"""
Validation utilities for iRacing League Session Auditor.
"""

import copy
import hashlib
import json
from typing import Dict, List, Any, Callable, Tuple, Union

# Constants for validation result formatting
PASS_ICON = "✅"
FAIL_ICON = "❌"
UNKNOWN_ICON = "🟡"


def compare_expectations(expected: Any, actual: Any, path: str = "") -> List[str]:
    """
    Recursively compare expected and actual values.

    Args:
        expected: The expected value or structure
        actual: The actual value or structure
        path: The current path in the structure for reporting

    Returns:
        List of validation results
    """
    results = []

    # Handle different types
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            results.append(
                f"{FAIL_ICON} {path} type mismatch: expected dict, got {type(actual).__name__}"
            )
            return results

        for k, v in expected.items():
            new_path = f"{path}.{k}" if path else k
            if k in actual:
                results.extend(compare_expectations(v, actual[k], new_path))
            else:
                results.append(f"{UNKNOWN_ICON} {new_path} NOT FOUND")

    elif isinstance(expected, list):
        if not isinstance(actual, list):
            results.append(
                f"{FAIL_ICON} {path} type mismatch: expected list, got {type(actual).__name__}"
            )
            return results

        for i, v in enumerate(expected):
            if i < len(actual):
                results.extend(compare_expectations(v, actual[i], f"{path}[{i}]"))
            else:
                results.append(f"{UNKNOWN_ICON} {path}[{i}] NOT FOUND in actual list")

    elif callable(expected):  # For matchers like CronMatcher
        ok, msg = expected(actual)
        if ok:
            results.append(f"{PASS_ICON} {path} {msg}")
        else:
            results.append(f"{FAIL_ICON} {path} {msg}")

    else:  # Direct comparison
        if expected == actual:
            results.append(f"{PASS_ICON} {path} correct: {actual}")
        else:
            results.append(f"{FAIL_ICON} {path} INCORRECT: {actual} != {expected}")

    return results


def count_mismatches(results: List[str]) -> int:
    """
    Count the number of mismatches in validation results.

    Args:
        results: List of validation result strings

    Returns:
        Number of mismatches
    """
    return sum(
        1
        for r in results
        if r.startswith(f"{FAIL_ICON}") or r.startswith(f"{UNKNOWN_ICON}")
    )


def session_hash(session: Dict[str, Any]) -> str:
    """
    Compute a hash of the session's relevant fields for change detection.

    Args:
        session: Session data to hash

    Returns:
        SHA-256 hash of the session
    """
    s = copy.deepcopy(session)

    # Remove fields that change frequently but don't affect validation
    try:
        del s["weather"]["weather_url"]
    except (KeyError, TypeError):
        pass

    try:
        del s["weather"]["forecast_options"]["weather_seed"]
    except (KeyError, TypeError):
        pass

    # Remove non-validation-related fields
    for key in [
        "elig",
        "can_spot",
        "can_watch",
        "can_broadcast",
        "can_join",
        "subsession_id",
    ]:
        try:
            del s[key]
        except KeyError:
            pass

    # Generate hash from JSON string
    return hashlib.sha256(json.dumps(s, sort_keys=True).encode()).hexdigest()


def format_validation_results(results: List[Dict[str, Any]]) -> str:
    """
    Format validation results for display.

    Args:
        results: List of validation results

    Returns:
        Formatted string with validation results
    """
    formatted_results = []

    for result in results:
        # Extract session name and results
        session_name = list(result.keys())[0]
        session_results = result[session_name]

        # Check if there are any failing validations
        validation_failures = [
            sr
            for sr in session_results
            if sr.startswith(f"{FAIL_ICON}") or sr.startswith(f"{UNKNOWN_ICON}")
        ]

        # If no failures, show a success message
        if not validation_failures:
            result_string = f"# {session_name}:\n{PASS_ICON} All checks passed!"
            result_string += (
                f"\n### Matched {result.get('matched_expectation_name', 'None')}"
            )
            formatted_results.append(result_string)
            continue

        # If we have failures and additional expectation results, show all of them
        result_string = f"# {session_name}:\n"

        # If there are additional expectations that were checked
        if "all_expectation_results" in result and result["all_expectation_results"]:
            all_exp_results = result["all_expectation_results"]

            # Add results for each expectation
            for exp_name, exp_results in all_exp_results.items():
                exp_failures = [
                    er
                    for er in exp_results
                    if er.startswith(f"{FAIL_ICON}") or er.startswith(f"{UNKNOWN_ICON}")
                ]
                if exp_failures:
                    result_string += f"\n### Failed Case: {exp_name}\n"
                    result_string += "\n".join(exp_failures)
                    result_string += "\n"
        else:
            # Fall back to just showing the failures from the best match
            result_string += "\n".join(validation_failures)

        formatted_results.append(result_string)

    return "\n\n".join(formatted_results)


def validate_session(
    session: Dict,
    expectations: List[Dict],
) -> Dict[str, Any]:
    """
    Validate a single session against expectations.

    Args:
        session: Session data to validate
        expectations: List of expectation dictionaries

    Returns:
        Dictionary containing validation results
    """
    if not isinstance(expectations, list):
        expectations = [expectations]

    best_result = None
    best_mismatches = None
    best_expectation = None
    best_name = None
    all_expectation_results = {}

    for exp in expectations:
        # Support both legacy (dict) and named (dict with 'name' and 'expectation') formats
        if isinstance(exp, dict) and "expectation" in exp and "name" in exp:
            name = exp["name"]
            expectation = exp["expectation"]
        else:
            name = None
            expectation = exp

        results = compare_expectations(expectation, session)
        mismatches = count_mismatches(results)

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
        "matched_expectation": best_expectation,
        "matched_expectation_name": best_name,
    }

    # Only include all_expectation_results if there are mismatches and multiple named expectations
    if best_mismatches > 0 and len(all_expectation_results) > 0:
        result["all_expectation_results"] = all_expectation_results

    return result

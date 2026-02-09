# -*- coding: utf-8 -*-
"""
Example tests demonstrating the use of conftest.py fixtures and helpers

These examples show how the shared fixtures and helper functions from conftest.py
can simplify test code and reduce duplication.

Note: The helper functions from conftest.py are automatically available in the test
namespace when using pytest. You can also import them explicitly using:
    from tests.conftest import parse_rule, assert_parse_success, etc.
"""
import pytest

# Import helper functions from conftest.py
# These are automatically available via pytest's conftest mechanism
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from conftest import (
    parse_rule,
    assert_parse_success,
    get_rules_by_type,
    find_action_by_attribute,
    count_actions_by_attribute,
    has_transformation,
)


# ============================================================================
# Example 1: Using parse_rule and assert_parse_success helpers
# ============================================================================

def test_example_with_helpers():
    """
    Before (old style):
        from secrules_parsing import parser
        rule_text = '...'
        parsed_rule = parser.process_from_str(rule_text)
        for rule in parsed_rule.rules:
            assert rule.__class__.__name__ == "SecRule"
            ...

    After (with helpers):
        Much cleaner and more readable!
    """
    rule_text = 'SecRule ARGS "@rx attack" "id:1001,phase:2,deny,t:lowercase"'

    # Parse and assert success in one line
    result = parse_rule(rule_text)
    assert_parse_success(result)

    # Get specific rule types
    sec_rules = get_rules_by_type(result, "SecRule")
    assert len(sec_rules) == 1

    rule = sec_rules[0]

    # Find specific action by attribute
    id_action = find_action_by_attribute(rule, 'id', 1001)
    assert id_action is not None
    assert id_action.id == 1001

    # Check for transformation
    assert has_transformation(rule, 'lowercase')


# ============================================================================
# Example 2: Using fixtures for common rule patterns
# ============================================================================

def test_example_with_fixtures(sample_secrule_basic, sample_secaction):
    """
    Using pre-defined rule fixtures instead of writing rule text in every test
    """
    # Use basic SecRule fixture
    result = parse_rule(sample_secrule_basic)
    assert_parse_success(result)

    rules = get_rules_by_type(result, "SecRule")
    assert len(rules) == 1

    # Use SecAction fixture
    action_result = parse_rule(sample_secaction)
    actions = get_rules_by_type(action_result, "SecAction")
    assert len(actions) == 1


# ============================================================================
# Example 3: Counting actions by attribute
# ============================================================================

def test_example_count_actions(sample_secrule_complex):
    """
    Using count_actions_by_attribute and find_action_by_attribute
    """
    result = parse_rule(sample_secrule_complex)
    assert_parse_success(result)

    rules = get_rules_by_type(result, "SecRule")
    rule = rules[0]

    # Find specific actions
    id_action = find_action_by_attribute(rule, 'id', 941181)
    assert id_action is not None
    assert id_action.id == 941181

    # Check phase
    phase_action = find_action_by_attribute(rule, 'phase', "2")
    assert phase_action is not None


# ============================================================================
# Example 4: Error handling made simple
# ============================================================================

def test_example_parse_error_handling():
    """
    Handling parse errors gracefully
    """
    # Intentionally bad syntax
    bad_rule = 'SecRule ARGS @rx "missing quotes'

    result = parse_rule(bad_rule)

    # Check if it's an error (returns dict instead of model)
    if isinstance(result, dict):
        assert 'message' in result
        assert 'line' in result
        # Test passes - we expected a parse error
        return

    # If we get here, parsing succeeded when it shouldn't have
    pytest.fail("Expected parse error but got success")


# ============================================================================
# Example 5: Using secrules_parser fixture
# ============================================================================

def test_example_parser_fixture(secrules_parser):
    """
    Using the parser fixture directly
    """
    rule_text = 'SecMarker TEST-MARKER'

    # Use parser fixture instead of importing parser module
    result = secrules_parser.process_from_str(rule_text)

    markers = get_rules_by_type(result, "SecMarker")
    assert len(markers) == 1
    assert markers[0].skipTag == "TEST-MARKER"


# ============================================================================
# Example 6: Complex assertion made simple
# ============================================================================

def test_example_complex_assertions():
    """
    Before: Multiple nested loops to find and verify actions
    After: Clean, readable helper-based assertions
    """
    rule_text = """
    SecRule ARGS "@rx injection" \
        "id:2001,\
        phase:2,\
        deny,\
        msg:'SQL Injection Detected',\
        severity:CRITICAL,\
        tag:'attack-sqli',\
        tag:'OWASP_CRS',\
        setvar:'tx.score=+5',\
        t:lowercase,\
        t:urlDecode"
    """

    result = parse_rule(rule_text)
    assert_parse_success(result)

    rule = get_rules_by_type(result, "SecRule")[0]

    # Simple assertions using helpers
    assert find_action_by_attribute(rule, 'id', 2001) is not None
    assert find_action_by_attribute(rule, 'severity', 'CRITICAL') is not None

    # Check for transformations
    assert has_transformation(rule, 'lowercase')
    assert has_transformation(rule, 'urlDecode')

    # Find specific phase
    phase_action = find_action_by_attribute(rule, 'phase', "2")
    assert phase_action is not None


# ============================================================================
# Example 7: Testing multiple rule types in one file
# ============================================================================

def test_example_multiple_directives():
    """
    Testing multiple directive types with clean helper usage
    """
    multi_rule = """
    SecMarker BEGIN-TESTS
    SecRule ARGS "@rx test" "id:3001,deny"
    SecAction "id:3002,pass,setvar:tx.test=1"
    SecMarker END-TESTS
    """

    result = parse_rule(multi_rule)
    assert_parse_success(result)

    # Count each type
    markers = get_rules_by_type(result, "SecMarker")
    rules = get_rules_by_type(result, "SecRule")
    actions = get_rules_by_type(result, "SecAction")

    assert len(markers) == 2
    assert len(rules) == 1
    assert len(actions) == 1

    # Verify marker tags
    assert markers[0].skipTag == "BEGIN-TESTS"
    assert markers[1].skipTag == "END-TESTS"

    # Verify rule ID
    assert find_action_by_attribute(rules[0], 'id', 3001) is not None

    # Verify action
    assert find_action_by_attribute(actions[0], 'varname', 'tx.test') is not None

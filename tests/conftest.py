"""
Pytest configuration and shared fixtures for secrules_parsing tests

This module provides common fixtures and helper functions used across all test files.
"""
import pytest
from typing import Any, Dict, List, Optional, Union
from secrules_parsing import parser


# ============================================================================
# Parser Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def secrules_parser():
    """
    Provide the secrules parser module as a fixture.

    Usage:
        def test_something(secrules_parser):
            result = secrules_parser.process_from_str("SecRule ARGS ...")
    """
    return parser


# ============================================================================
# Helper Functions (available as imports, not fixtures)
# ============================================================================

def parse_rule(rule_text: str) -> Union[Any, Dict[str, Any]]:
    """
    Parse a rule text and return the parsed result.

    Returns the parsed model object on success, or a dict with error info on failure.

    Args:
        rule_text: ModSecurity rule text to parse

    Returns:
        Parsed model object or dict with keys: 'line', 'col', 'message'

    Example:
        result = parse_rule('SecRule ARGS "@rx attack" "id:1,deny"')
        if isinstance(result, dict):
            # Parse error
            print(f"Error: {result['message']}")
        else:
            # Success
            for rule in result.rules:
                print(rule.__class__.__name__)
    """
    return parser.process_from_str(rule_text)


def assert_parse_success(parsed_result: Union[Any, Dict]) -> None:
    """
    Assert that parsing was successful (not a dict error response).

    Args:
        parsed_result: Result from parse_rule() or parser.process_from_str()

    Raises:
        AssertionError: If parsing failed

    Example:
        result = parse_rule(rule_text)
        assert_parse_success(result)
        # Now safe to use result.rules
    """
    assert not isinstance(parsed_result, dict), \
        f"Parse failed: {parsed_result.get('message', 'Unknown error')} at line {parsed_result.get('line', '?')}"


def get_rules_by_type(parsed_result: Any, rule_type: str) -> List[Any]:
    """
    Get all rules of a specific type from parsed result.

    Args:
        parsed_result: Parsed model object
        rule_type: Rule type name (e.g., "SecRule", "SecAction", "SecMarker")

    Returns:
        List of rules matching the specified type

    Example:
        result = parse_rule(rule_text)
        sec_rules = get_rules_by_type(result, "SecRule")
        assert len(sec_rules) == 2
    """
    if isinstance(parsed_result, dict):
        return []
    return [rule for rule in parsed_result.rules if rule.__class__.__name__ == rule_type]


def find_action_by_attribute(rule: Any, attr_name: str, attr_value: Any = None) -> Optional[Any]:
    """
    Find an action in a rule by attribute name and optionally value.

    Args:
        rule: Parsed rule object
        attr_name: Attribute name to search for (e.g., 'id', 'msg', 'severity')
        attr_value: Optional value to match (if None, just checks attribute exists)

    Returns:
        First matching action or None

    Example:
        rule = get_rules_by_type(result, "SecRule")[0]
        id_action = find_action_by_attribute(rule, 'id', 1000)
        assert id_action.id == 1000
    """
    if not hasattr(rule, 'actions'):
        return None

    for action in rule.actions:
        if hasattr(action, attr_name):
            if attr_value is None:
                return action
            if getattr(action, attr_name) == attr_value:
                return action
    return None


def count_actions_by_attribute(rule: Any, attr_name: str, attr_value: Any = None) -> int:
    """
    Count actions in a rule matching an attribute name and optionally value.

    Args:
        rule: Parsed rule object
        attr_name: Attribute name to search for
        attr_value: Optional value to match

    Returns:
        Number of matching actions

    Example:
        rule = get_rules_by_type(result, "SecRule")[0]
        tag_count = count_actions_by_attribute(rule, 'tag')
        assert tag_count == 3
    """
    if not hasattr(rule, 'actions'):
        return 0

    count = 0
    for action in rule.actions:
        if hasattr(action, attr_name):
            if attr_value is None or getattr(action, attr_name) == attr_value:
                count += 1
    return count


def has_transformation(rule: Any, transformation: str) -> bool:
    """
    Check if a rule has a specific transformation.

    Args:
        rule: Parsed rule object
        transformation: Transformation name (e.g., 'lowercase', 'urlDecode')

    Returns:
        True if the rule has the transformation

    Example:
        rule = get_rules_by_type(result, "SecRule")[0]
        assert has_transformation(rule, 'lowercase')
    """
    if not hasattr(rule, 'actions'):
        return False

    for action in rule.actions:
        if hasattr(action, 'transformations') and action.transformations:
            if transformation in action.transformations:
                return True
    return False


# ============================================================================
# Sample Rule Fixtures
# ============================================================================

@pytest.fixture(scope="function")
def sample_secrule_basic():
    """Simple SecRule for basic testing"""
    return 'SecRule ARGS "@rx attack" "id:1,phase:2,deny"'


@pytest.fixture(scope="function")
def sample_secrule_complex():
    """Complex SecRule with multiple actions and transformations"""
    return """
    SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@contains -->" \
     "id:941181,\
     phase:2,\
     block,\
     capture,\
     t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:lowercase,t:removeNulls,\
     msg:'Node-Validator Deny List Keywords',\
     logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
     tag:'application-multi',\
     tag:'language-multi',\
     tag:'platform-multi',\
     tag:'attack-xss',\
     tag:'paranoia-level/2',\
     tag:'OWASP_CRS',\
     tag:'capec/1000/152/242',\
     ctl:auditLogParts=+E,\
     ver:'OWASP_CRS/4.0.0-rc1',\
     severity:'CRITICAL',\
     setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
     setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
    """


@pytest.fixture(scope="function")
def sample_secaction():
    """Simple SecAction for testing"""
    return 'SecAction "id:1000,phase:1,pass,setvar:tx.test=value"'


@pytest.fixture(scope="function")
def sample_secmarker():
    """Simple SecMarker for testing"""
    return 'SecMarker BEGIN-TEST-RULES'


# ============================================================================
# Legacy Fixtures (kept for backward compatibility)
# ============================================================================

@pytest.fixture(scope="function")
def contains_rule():
    """Legacy fixture - use sample_secrule_complex instead"""
    return """
 SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@contains -->" \
     "id:941181,\
     phase:2,\
     block,\
     capture,\
     t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:lowercase,t:removeNulls,\
     msg:'Node-Validator Deny List Keywords',\
     logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
     tag:'application-multi',\
     tag:'language-multi',\
     tag:'platform-multi',\
     tag:'attack-xss',\
     tag:'paranoia-level/2',\
     tag:'OWASP_CRS',\
     tag:'capec/1000/152/242',\
     ctl:auditLogParts=+E,\
     ver:'OWASP_CRS/4.0.0-rc1',\
     severity:'CRITICAL',\
     setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
     setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
     """


@pytest.fixture(scope="package")
def test_template():
    """Test template for generating test cases"""
    return """
---
meta:
  author: "secrules_parser"
  description: Automatically generated
  enabled: true
  name: test.yaml
tests:
  - test_title: {{ test_title }}
    desc: {{ desc }}
    stages:
      - stage:
          input:
            dest_addr: 127.0.0.1
            headers:
              Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
              Host: localhost
              User-Agent: OWASP CRS
            method: {{ method }}
            port: 80
            uri: "{{ uri }}
          output:
            log_contains: id "{{ id }}"
"""

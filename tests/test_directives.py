# -*- coding: utf-8 -*-
"""
Test suite for ModSecurity directives
Tests parsing of different directive types: SecMarker, SecComponentSignature,
SecRuleRemoveById, SecRuleRemoveByTag, SecRuleUpdateTargetById,
SecRuleUpdateTargetByTag, SecRuleScript
"""
from secrules_parsing import parser


# SecMarker Directive Tests


def test_sec_marker_directive() -> None:
    """
        Test that SecMarker directive works correctly
    """
    rule_text = """
    SecMarker BEGIN-WORDPRESS-RULES
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecMarker"
        if rule.skipTag == "BEGIN-WORDPRESS-RULES":
            matches += 1
    assert matches == 1


def test_sec_marker_with_quotes() -> None:
    """
        Test that SecMarker directive works with quoted tags
    """
    rule_text = """
    SecMarker "END-REQUEST-920-PROTOCOL-ENFORCEMENT"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecMarker"
        if rule.skipTag == "END-REQUEST-920-PROTOCOL-ENFORCEMENT":
            matches += 1
    assert matches == 1


# SecComponentSignature Directive Test


def test_sec_component_signature() -> None:
    """
        Test that SecComponentSignature directive works correctly
    """
    rule_text = """
    SecComponentSignature "OWASP_CRS/4.0.0"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecComponentSignature"
        if rule.signature == "OWASP_CRS/4.0.0":
            matches += 1
    assert matches == 1


# SecRuleRemoveById Directive Tests


def test_sec_rule_remove_by_id_single() -> None:
    """
        Test that SecRuleRemoveById works with a single ID
    """
    rule_text = """
    SecRuleRemoveById 920100
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRuleRemoveById"
        if hasattr(rule.ids, 'idlist') and 920100 in rule.ids.idlist:
            matches += 1
    assert matches == 1


def test_sec_rule_remove_by_id_range() -> None:
    """
        Test that SecRuleRemoveById works with a range of IDs
    """
    rule_text = """
    SecRuleRemoveById "920100-920200"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRuleRemoveById"
        if hasattr(rule.ids, 'range') and rule.ids.range:
            matches += 1
    assert matches == 1


# SecRuleRemoveByTag Directive Test


def test_sec_rule_remove_by_tag() -> None:
    """
        Test that SecRuleRemoveByTag works correctly
    """
    rule_text = """
    SecRuleRemoveByTag attack-sqli
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRuleRemoveByTag"
        if rule.tag == "attack-sqli":
            matches += 1
    assert matches == 1


# SecRuleUpdateTargetById Directive Tests


def test_sec_rule_update_target_by_id() -> None:
    """
        Test that SecRuleUpdateTargetById works correctly
    """
    rule_text = """
    SecRuleUpdateTargetById 942100 !ARGS:username
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRuleUpdateTargetById"
        if rule.id == 942100:
            matches += 1
            for target in rule.targets:
                if target.negated and target.variables.collection == "ARGS":
                    if target.variables.collectionArg == "username":
                        matches += 1
    assert matches == 2


def test_sec_rule_update_target_by_id_multiple_targets() -> None:
    """
        Test that SecRuleUpdateTargetById works with multiple targets
    """
    rule_text = """
    SecRuleUpdateTargetById 942100 !ARGS:username,!ARGS:password
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRuleUpdateTargetById"
        if rule.id == 942100:
            matches += 1
            target_count = len(rule.targets)
            assert target_count == 2
            matches += target_count
    assert matches == 3


# SecRuleUpdateTargetByTag Directive Tests


def test_sec_rule_update_target_by_tag() -> None:
    """
        Test that SecRuleUpdateTargetByTag works correctly
    """
    rule_text = """
    SecRuleUpdateTargetByTag "attack-sqli" !ARGS:search
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRuleUpdateTargetByTag"
        if rule.tag == "attack-sqli":
            matches += 1
            for target in rule.targets:
                if target.negated and target.variables.collection == "ARGS":
                    if target.variables.collectionArg == "search":
                        matches += 1
    assert matches == 2


def test_sec_rule_update_target_by_tag_unquoted() -> None:
    """
        Test that SecRuleUpdateTargetByTag works without quotes
    """
    rule_text = """
    SecRuleUpdateTargetByTag attack-xss !REQUEST_COOKIES
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRuleUpdateTargetByTag"
        if rule.tag == "attack-xss":
            matches += 1
    assert matches == 1


# SecRuleScript Directive Tests


def test_sec_rule_script_basic() -> None:
    """
        Test that SecRuleScript directive works correctly
    """
    rule_text = """
    SecRuleScript /path/to/script.lua "id:1000,phase:2,pass"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRuleScript"
        if rule.script == "/path/to/script.lua":
            matches += 1
            for action in rule.actions:
                if hasattr(action, 'id') and action.id == 1000:
                    matches += 1
    assert matches == 2


def test_sec_rule_script_quoted() -> None:
    """
        Test that SecRuleScript works with quoted script path
    """
    rule_text = """
    SecRuleScript "/usr/local/modsecurity/scripts/check.lua" "id:2000,phase:1,deny"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRuleScript"
        if rule.script == "/usr/local/modsecurity/scripts/check.lua":
            matches += 1
    assert matches == 1

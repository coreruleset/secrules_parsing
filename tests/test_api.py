# -*- coding: utf-8 -*-
import glob
import os
import re

from secrules_parsing import parser


def test_api() -> None:
    """Test that usage as API works"""
    # Extract all of our pathing
    files = glob.glob("../../rules/*.conf")
    # Pass absolute paths because of module location
    files = [os.path.abspath(path) for path in files]
    models = parser.process_rules(files)


def test_model_parse() -> None:
    """Test that we can parse the model correctly"""
    rule_text = """
    SecRule ARGS "@rx found" "id:1,log,noauditlog,t:lowercase,block"
    SecRule FILES:pluginzip "@endsWith .zip" "id:2,phase:2,pass,t:none,ctl:ruleRemoveTargetById=944110;REQUEST_BODY,ctl:ruleRemoveTargetById=944250;REQUEST_BODY"
    """
    parsed_rule = parser.process_from_str(rule_text)
    # print(ppretty(parsed_rule, depth=10))
    for rule in parsed_rule.rules:
        assert (rule.__class__.__name__) == "SecRule"
        for var in rule.variables:
            assert var.collection in ["ARGS", "FILES"]


def test_operator_contains_works_with_greater_than() -> None:
    """Test that the contains operator works correctly using greater than"""
    rule_text = """
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

    parsed_rule = parser.process_from_str(rule_text)
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        assert rule.operator.contains == "-->"


def test_collection_argument_with_dollar() -> None:
    """Test that a collection argument can contain `$` (e.g., a key in a JSON document)"""
    rule_text = """
    SecRule REQUEST_FILENAME "@rx /apps/mail/api/messages/[0-9]+/flags$" \
    "id:9508978,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    ver:'nextcloud-rule-exclusions-plugin/1.0.0',\
    ctl:ruleRemoveTargetById=942290;ARGS_NAMES:json.flags.$notjunk,\
    setvar:'tx.allowed_methods=%{tx.allowed_methods} PUT'"
    """

    parsed_rule = parser.process_from_str(rule_text)
    matched = False
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        for action in rule.actions:
            if action.ctl:
                matched = True
                assert action.ctl.ruleRemoveTargetById == 942290
                assert action.ctl.removeVariableName == "json.flags.$notjunk"

    assert matched


def test_lowercase_and_uppercase_in_argument() -> None:
    """ Example test showing how to find if a rule has a lowercase transformation, then see if the target
    of the rule has an uppercase regex. """
    rule_text = """
    SecRule REQUEST_FILENAME "@rx /[ABCD]+/$" \
    "id:1234,\
    phase:1,\
    pass,\
    t:lowercase,\
    nolog
    """

    matched = False
    uppercase_regex = re.compile(r"[A-Z]")
    parsed_rule = parser.process_from_str(rule_text)
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        for action in rule.actions:
            if action.transformations:
                for t in action.transformations:
                    if t == "lowercase":
                        if uppercase_regex.search(rule.operator.rx):
                            matched = True
                            assert True, ("Regex tries to match uppercase, "
                                          "but you are transforming into lowercase so it will "
                                          "never match")

    assert matched

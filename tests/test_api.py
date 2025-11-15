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
                assert action.ctl.removeVariable.collection == "ARGS_NAMES"
                assert action.ctl.removeVariable.collectionArg == "json.flags.$notjunk"

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

def test_use_collection_keys() -> None:
    """Test if the collection keys work as we expected"""
    rule_text = """
    SecRule ARGS_NAMES|!ARGS_NAMES:/^foo$/|!ARGS_NAMES:/^bar*?$/|ARGS "@rx found" "id:1,log,noauditlog,t:lowercase,block"
    """
    parsed_rule = parser.process_from_str(rule_text)
    # print(ppretty(parsed_rule, depth=10))
    for rule in parsed_rule.rules:
        assert (rule.__class__.__name__) == "SecRule"
        for var in rule.variables:
            assert var.collection in ["ARGS_NAMES", "ARGS"]
            if var.collection == "ARGS_NAMES":
                assert var.collectionArg in [None, "/^foo$/", "/^bar*?$/"]

def test_use_commas_in_setvar() -> None:
    """
        Test if the value of the 'setvar' action arguments contains ',' (comma),
        '<' (less than) or '>' (greater than) character
    """
    rule_text = """
    SecRule TX:FALSE-POSITIVE-REPORT-PLUGIN_FILTER_IP "@gt 0" \
        "id:9525140,\
        phase:5,\
        pass,\
        t:none,t:length,\
        nolog,\
        setvar:'tx.false-positive-report-plugin_remote_addr=,%{remote_addr},',\
        setvar:'tx.false-positive-report-plugin_smtp_subject=<server_hostname> - <host_header>: False positive report from CRS'"
    """
    parsed_rule = parser.process_from_str(rule_text)
    # print(ppretty(parsed_rule, depth=10))
    matches = 0
    for rule in parsed_rule.rules:
        assert (rule.__class__.__name__) == "SecRule"
        for act in rule.actions:
            if act.varname == "tx.false-positive-report-plugin_remote_addr" and \
               act.macro   == ",%{remote_addr},":
                   matches += 1
            if act.varname == "tx.false-positive-report-plugin_smtp_subject" and \
               act.macro   == "<server_hostname> - <host_header>: False positive report from CRS":
                   matches += 1
        assert(matches == 2)

def test_use_multi_ids_in_setvar_arg() -> None:
    """
        Test if the value of the 'setvar' action arguments contains multiple
        numbers (rule ID's)
    """
    rule_text = """
        SecAction \
          "id:9525020,\
          phase:5,\
          nolog,\
          pass,\
          t:none,\
          ver:'false-positive-report-plugin/1.0.0',\
          setvar:'tx.false-positive-report-plugin_filter_ignore_id=949110 959100 980130 980140'"
    """
    parsed_rule = parser.process_from_str(rule_text)
    # print(ppretty(parsed_rule, depth=10))
    matches = 0
    for rule in parsed_rule.rules:
        assert (rule.__class__.__name__) == "SecAction"
        for act in rule.actions:
            if act.varname == "tx.false-positive-report-plugin_filter_ignore_id" and \
               act.macro   == "949110 959100 980130 980140":
                   matches += 1
        assert(matches == 1)

def test_check_collection_keys() -> None:
    """
        Test if the rule looks for a specific key in collection
    """
    rule_text = """
        SecRule ARGS:foobar "@rx attack" \
          "id:1,\
          phase:1,\
          nolog,\
          pass,\
          t:none"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        for v in rule.variables:
            assert(v.collectionArg == "foobar")

def test_check_collection_keys_in_target_exclusion() -> None:
    """
        Test if the rule looks for a specific key in collection
    """
    rule_text = """
        SecRule REQUEST_URI "@beginsWith /admin" \
          "id:1,\
          phase:1,\
          nolog,\
          pass,\
          t:none,\
          ctl:ruleRemoveTargetById=921180;TX:paramcounter_ARGS_NAMES:folders.folders,\
          ctl:ruleRemoveTargetByTag=OWASP;TX:paramcounter_ARGS_NAMES:folders.folders,\
          ctl:ruleRemoveTargetByMsg='multi target';TX:paramcounter_ARGS_NAMES:folders.folders"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0

    for rule in parsed_rule.rules:
        for action in rule.actions:
            if action.ctl:
                if action.ctl.ruleRemoveTargetById == 921180:
                    matches += 1
                if action.ctl.tagName == "OWASP":
                    matches += 1
                if action.ctl.message == "'multi target'":
                    matches += 1
                if action.ctl.removeVariable.collection == "TX":
                    matches += 1
                if action.ctl.removeVariable.collectionArg == "paramcounter_ARGS_NAMES":
                    matches += 1
                if action.ctl.removeVariableKey == "folders.folders":
                    matches += 1
    # 3 exclusions, matches argument (ID, tag, msg) -> 3, collection (TX) -> 3,
    # collection arg (paramcounter_ARGS_NAMES) -> 3, arg key (folders.folders) -> 3
    # total 12
    assert (matches == 12)


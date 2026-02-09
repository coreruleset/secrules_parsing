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


def test_collection_cidr() -> None:
    """Test that a collection argument can contain a CIDR."""
    rule_text = """
    SecRule REMOTE_ADDR "@ipMatch 8.8.8.0/24" "id:1,phase:2,pass"
    SecRule REMOTE_ADDR "@ipMatch 2001:db8::/32" "id:1,phase:2,pass"
    """

    parsed_rule = parser.process_from_str(rule_text)
    matched = False
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        for action in rule.actions:
        #TODO

    assert matched


def test_collection_env() -> None:
    """Test that a collection argument can contain an environment variable."""
    rule_text = """
    SecRule REQUEST_URI "@rx .?" "id:1,phase:2,pass,setenv:my_env=my_env_value"
    """

    parsed_rule = parser.process_from_str(rule_text)
    matched = False
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        #TODO

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
          ctl:ruleRemoveTargetById=921180;ARGS_NAMES,\
          ctl:ruleRemoveTargetById=921180;ARGS_NAMES:folders.folders,\
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
                if action.ctl.removeVariable.collection == "ARGS_NAMES":
                    matches += 1
                if action.ctl.removeVariable.collection == "TX":
                    matches += 1
                if action.ctl.removeVariable.collectionArg == "folders.folders":
                    matches += 1
                if action.ctl.removeVariable.collectionArg == "paramcounter_ARGS_NAMES":
                    matches += 1
                if action.ctl.removeVariableKey == "folders.folders":
                    matches += 1
    # 1st excl: ID, collection (ARGS_NAMES) -> 2
    # 2nd excl: ID, collection (ARGS_NAMES), coll arg (folders.folders) -> 3
    # 3rd excl: ID, collection (TX), coll arg (paramcounter_ARGS_NAMES), coll arg (folders.folders) -> 4
    # 4th excl: tag, collection (TX), coll arg (paramcounter_ARGS_NAMES), coll arg (folders.folders) -> 4
    # 5th excl: msg, collection (TX), coll arg (paramcounter_ARGS_NAMES), coll arg (folders.folders) -> 4
    # total 17
    assert (matches == 17)


def test_setenv_unquoted_syntax() -> None:
    """
        Test that setenv action works with unquoted syntax (issue #92)
        This test verifies the fix in PR #93
    """
    rule_text = """
    SecRule ARGS "@rx ^.{3,}$" \
        "id:1,\
        phase:2,\
        pass,\
        setenv:my_env=my_env_value"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        for act in rule.actions:
            if act.varname == "my_env" and act.macro == "my_env_value":
                matches += 1
    assert matches == 1


def test_setenv_quoted_syntax() -> None:
    """
        Test that setenv action works with quoted syntax (issue #92)
        This test verifies the fix in PR #93
    """
    rule_text = """
    SecRule ARGS "@rx ^.{3,}$" \
        "id:2,\
        phase:2,\
        pass,\
        setenv:'my_env=my_env_value'"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        for act in rule.actions:
            if act.varname == "my_env" and act.macro == "my_env_value":
                matches += 1
    assert matches == 1


def test_setenv_with_macro() -> None:
    """
        Test that setenv action works with macro values
        This test verifies the fix in PR #93
    """
    rule_text = """
    SecRule ARGS "@rx attack" \
        "id:3,\
        phase:2,\
        pass,\
        setenv:'detected_attack=%{tx.anomaly_score}'"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        for act in rule.actions:
            if act.varname == "detected_attack" and act.macro == "%{tx.anomaly_score}":
                matches += 1
    assert matches == 1


def test_setenv_deletion_quoted() -> None:
    """
        Test that setenv action works with deletion syntax (quoted)
        This test verifies the fix in PR #93
    """
    rule_text = """
    SecRule REQUEST_URI "@beginsWith /safe" \
        "id:4,\
        phase:1,\
        pass,\
        setenv:'!suspicious_request'"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        for act in rule.actions:
            if act.varname == "suspicious_request" and not act.macro:
                matches += 1
    assert matches == 1


def test_setenv_deletion_unquoted() -> None:
    """
        Test that setenv action works with deletion syntax (unquoted)
        This test verifies the fix in PR #93
    """
    rule_text = """
    SecRule REQUEST_URI "@beginsWith /safe" \
        "id:5,\
        phase:1,\
        pass,\
        setenv:!suspicious_request"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        for act in rule.actions:
            if act.varname == "suspicious_request" and not act.macro:
                matches += 1
    assert matches == 1


def test_setenv_with_special_characters() -> None:
    """
        Test that setenv action works with special characters in values
        This test verifies the fix in PR #93
    """
    rule_text = """
    SecRule ARGS "@rx attack" \
        "id:6,\
        phase:2,\
        pass,\
        setenv:'log_message=Attack detected: %{MATCHED_VAR}',\
        setenv:log_level=warning"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        for act in rule.actions:
            if act.varname == "log_message" and act.macro == "Attack detected: %{MATCHED_VAR}":
                matches += 1
            if act.varname == "log_level" and act.macro == "warning":
                matches += 1
    assert matches == 2


def test_setenv_without_value() -> None:
    """
        Test that setenv action works with just a variable name (no value)
        This test verifies the fix in PR #93
    """
    rule_text = """
    SecRule REQUEST_METHOD "@streq POST" \
        "id:7,\
        phase:1,\
        pass,\
        setenv:'is_post='"
    """
    parsed_rule = parser.process_from_str(rule_text)
    matches = 0
    for rule in parsed_rule.rules:
        assert rule.__class__.__name__ == "SecRule"
        for act in rule.actions:
            if act.varname == "is_post" and (act.macro == "" or act.macro is None):
                matches += 1
    assert matches == 1


# Parse Error Context Tests


def test_parse_error_includes_context_field() -> None:
    """
    Test that parse errors include the 'context' field
    This verifies that error responses contain context information
    """
    rule_text = """
    SecRule ARGS @rx "missing quotes
    """
    result = parser.process_from_str(rule_text)

    # Should return error dict, not a model
    assert isinstance(result, dict), "Expected parse error to return dict"

    # Verify all error fields are present
    assert 'line' in result, "Error should include line number"
    assert 'col' in result, "Error should include column number"
    assert 'message' in result, "Error should include error message"
    assert 'context' in result, "Error should include context field"

    # Verify context is not None or empty
    assert result['context'] is not None, "Context should not be None"
    assert len(str(result['context'])) > 0, "Context should not be empty"


def test_parse_error_context_with_invalid_directive() -> None:
    """
    Test that invalid directive syntax provides context
    """
    rule_text = """
    InvalidDirective ARGS "@rx test"
    """
    result = parser.process_from_str(rule_text)

    assert isinstance(result, dict), "Expected parse error"
    assert 'context' in result, "Error should include context"
    assert result['line'] > 0, "Should have line number"
    assert result['col'] > 0, "Should have column number"


def test_parse_error_context_with_missing_operator() -> None:
    """
    Test that incomplete operator syntax provides context
    """
    rule_text = """
    SecRule ARGS @ "id:1,deny"
    """
    result = parser.process_from_str(rule_text)

    assert isinstance(result, dict), "Expected parse error"
    assert 'context' in result, "Error should include context"
    assert 'message' in result, "Error should include message"


def test_parse_error_context_with_malformed_actions() -> None:
    """
    Test that malformed actions provide context
    """
    rule_text = """
    SecRule ARGS "@rx test" "id:,phase:2"
    """
    result = parser.process_from_str(rule_text)

    assert isinstance(result, dict), "Expected parse error"
    assert 'context' in result, "Error should include context"
    assert result['line'] > 0, "Should have line number"


def test_parse_error_context_with_unclosed_quotes() -> None:
    """
    Test that unclosed quotes provide context
    """
    rule_text = """
    SecRule ARGS "@rx test" "id:1,msg:'unclosed message
    """
    result = parser.process_from_str(rule_text)

    assert isinstance(result, dict), "Expected parse error"
    assert 'context' in result, "Error should include context"
    assert 'line' in result, "Error should include line"
    assert 'col' in result, "Error should include col"


def test_successful_parse_does_not_return_dict() -> None:
    """
    Test that successful parses return model, not dict
    This ensures we can distinguish between success and error
    """
    rule_text = """
    SecRule ARGS "@rx test" "id:1,phase:2,deny"
    """
    result = parser.process_from_str(rule_text)

    # Successful parse should NOT return a dict
    assert not isinstance(result, dict), "Successful parse should return model, not dict"

    # Should have rules attribute
    assert hasattr(result, 'rules'), "Model should have rules attribute"
    assert len(result.rules) > 0, "Should have at least one rule"


def test_parse_error_context_multiline() -> None:
    """
    Test that parse errors in multiline rules include context
    """
    rule_text = """
    SecRule ARGS "@rx test" \\
        "id:1,\\
        phase:2,\\
        invalid_action_here,\\
        deny"
    """
    result = parser.process_from_str(rule_text)

    assert isinstance(result, dict), "Expected parse error"
    assert 'context' in result, "Error should include context"
    assert result['line'] > 0, "Should have line number"


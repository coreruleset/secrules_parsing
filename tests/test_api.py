# -*- coding: utf-8 -*-
import glob
import os
from secrules_parsing import parser

import pprint

def test_api():
    """Test that usage as API works"""
    # Extract all of our pathing
    files = glob.glob("../../rules/*.conf")
    # Pass absolute paths because of module location
    files = [os.path.abspath(path) for path in files]
    models = parser.process_rules(files)


def test_simple_rule():
    """Test that we can parse the model correctly"""
    rule_text = """
    SecRule ARGS "@rx found" "id:1,log,noauditlog,t:lowercase,block" 
    """
    parsed_rule = parser.process_from_str(rule_text)
    
    rule = parsed_rule.rules[0]

    assert rule.get_id() == 1, "rule ID should be 1"
    assert rule.get_parent_id() == 0, "rule is not a chained rule, parent_id should be 0"
    assert rule.chained == False, "rule is not a chained rule"
    assert rule.operator.name == 'rx', "operator is regexp"
    assert rule.operator.value == 'found', "regexp value should be 'found'"

def test_simple_chained_rule():
    """Test chained rules"""
    rule_text = """
    SecRule ARGS "@rx /test_chained" "id:50,log,noauditlog,t:lowercase,block,chain" \
        SecRule REQUEST_METHOD "@eq HEAD"
    """
    parsed_rule = parser.process_from_str(rule_text)
    
    rule1 = parsed_rule.rules[0]

    assert rule1.get_id() == 50, "rule ID should be 50"
    assert rule1.get_parent_id() == 0, "rule is not a chained rule, parent_id should be 0"
    assert rule1.chained == True, "rule has a chained rule"
    assert rule1.operator.name == 'rx', "operator is regexp"
    assert rule1.operator.value == '/test_chained', "regexp value should be '/test_chained'"

    rule2 = parsed_rule.rules[1]

    assert rule2.get_id() == None, "rule ID should be None, get its ID from parent"
    assert rule2.get_parent_id() == 50, "rule is not chained, but has parent_id so it is part of a chain"
    assert rule2.chained == False, "rule is not a chained rule"
    assert rule2.operator.name == 'eq', "operator is regexp"
    assert rule2.operator.value == 'HEAD', "operator value should be 'HEAD'"


def test_multiple_chained_rule():
    """Test multiple chained rules"""
    rule_text = """
    SecRule REQUEST_URI "@rx /one" "id:100,nolog,noauditlog,t:none,pass,chain" \
        SecRule ARGS "@streq something" "t:none,chain" \
            SecRule REQUEST_METHOD "@eq POST"
    """
    parsed_rule = parser.process_from_str(rule_text)
    
    rule1 = parsed_rule.rules[0]

    assert rule1.get_id() == 100, "rule ID should be 100"
    assert rule1.get_parent_id() == 0, "rule is not a chained rule, parent_id should be 0"
    assert rule1.chained == True, "rule has a chained rule"
    assert rule1.operator.name == 'rx', "operator is regexp"
    assert rule1.operator.value == '/one', "regexp value should be '/one'"

    rule2 = parsed_rule.rules[1]

    assert rule2.get_id() == None, "rule ID should be None, get its ID from parent"
    assert rule2.get_parent_id() == 100, "rule is not chained, but has parent_id so it is part of a chain"
    assert rule2.chained == True, "rule is a chained rule"
    assert rule2.operator.name == 'streq', "operator is streq"
    assert rule2.operator.value == 'something', "regexp value should be 'something'"

    rule3 = parsed_rule.rules[2]

    assert rule3.get_id() == None, "rule ID should be None, get its ID from parent"
    assert rule3.get_parent_id() == 100, "rule is not chained, but has parent_id so it is part of a chain"
    assert rule3.chained == False, "rule is not a chained rule"
    assert rule3.operator.name == 'eq', "operator is eq"
    assert rule3.operator.value == 'POST', "regexp value should be 'POST'"

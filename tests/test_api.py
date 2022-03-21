# -*- coding: utf-8 -*-
import glob
import os
from secrules_parsing import parser
from ppretty import ppretty

def test_api():
    """ Test that usage as API works """
    # Extract all of our pathing
    files = glob.glob("../../rules/*.conf")
    # Pass absolute paths because of module location
    files = [os.path.abspath(path) for path in files]
    models = parser.process_rules(files)


def test_model_parse():
    """ Test that we can parse the model correctly """
    rule_text = """
    SecRule ARGS "@rx found" "id:1,log,noauditlog,t:lowercase,block" 
    """
    parsed_rule = parser.process_from_str(rule_text)
    # print(ppretty(parsed_rule, depth=10))
    for rule in parsed_rule.rules:
        assert (rule.__class__.__name__) == "SecRule"
        for var in rule.variables:
            assert (var.collection == "ARGS")
           

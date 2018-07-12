#!/usr/bin/env python

""""
SecRules CRS Parser
-----------------------------------------------

Copyright (C) 2017 Felipe Zipitria <felipe.zipitria@owasp.org>

This program is free software; you can redistribute it and/or
modify it under the terms of the Apache License 2.0.

"""

import sys
import argparse
from textx.metamodel import metamodel_from_file
from textx.exceptions import TextXSyntaxError
import json


def parse_args():
    """ Parse our command line arguments """
    cmdline = argparse.ArgumentParser(description='ModSecurity CRS parser script.')
    cmdline.add_argument('-r', '--regex', help='Extract regular expressions from rules', action="store_true")
    cmdline.add_argument('-c', '--correctness', help='Check the validity of the syntax', action="store_true")
    cmdline.add_argument('-f', '--files', metavar='FILE', required=True, nargs='*', help='files to read, if empty, stdin is used')
    cmdline.add_argument('-v', '--verbose', help='Print verbose messages', action="store_true")
    cmdline.add_argument('-d', '--debug', help='You don\'t want to do this!', action="store_true")
    cmdline.add_argument('-o', '--output', metavar='FILE', help='Output results to file')
    myargs = cmdline.parse_args()
    return myargs


def process_rules(args):
    """ Parse our rule files with the provided parser """
    models = []
    # Load Meta-Model
    modsec_mm = metamodel_from_file('secrules.tx', memoization=True)
    # Register test processor
    modsec_mm.register_obj_processors({'SecRule': secrule_id_processor})
    for rule_file in args.files:
        if args.verbose:
            print('Processing file %s:' % rule_file)
        try:
            model = modsec_mm.model_from_file(rule_file)
        except TextXSyntaxError as e:
            model = {"Error":"Syntax error in line %d col %d: %s" % (e.line, e.col, e.message)}
        models.append(model)
    return models


def secrule_id_processor(rule):
    """ Processor for each rule, if needed """
    pass


def call_activites(args, models):
    """ For firing actions based on CLI args """
    if args.correctness:
        for file_index in range(0, len(args.files)):
            if isinstance(models[file_index], dict):
                print("Syntax invalid: %s" % models[file_index])
            else:
                get_correctness(args, args.files[file_index])
    if args.regex:
        regexs = {}
        for file_index in range(0, len(args.files)):
            output_regex = []
            for rule in models[file_index].rules:
                rule_regex = get_rule_regex(rule)
                if rule_regex is not None:
                    output_regex.append(rule_regex)
            regexs[args.files[file_index]] = output_regex
        print(json.dumps(regexs))


def create_output(output_loc):
    """ If output is specified we modify running """
    if output_loc is not None:
        sys.stdout = open(output_loc, 'w')


def get_rule_id(rule):
    """ Gets rule ID. Only for a given SecAction or SecRule """
    if rule.__class__.__name__ == "SecRule" or rule.__class__.__name__ == "SecAction":
        for action in rule.actions:
            if action.id:
                return action.id
    return 0


def get_rule_regex(rule):
    """ Gets the regex. Only for a given SecAction or SecRule """
    if rule.__class__.__name__ == "SecRule" or rule.__class__.__name__ == "SecAction":
        output = {}
        if rule.operator.rx is not None:
            for action in rule.actions:
                if action.id:
                    if action.id in output.keys():
                        output[action.id].append(rule.operator.rx)
                    else:
                        output[action.id] = [rule.operator.rx]
                    return output
        return None


def get_correctness(args, file):
    """ Checks the correctness of a given rules file """
    print("Syntax OK: %s" % (file))
    return True


if __name__ == "__main__":
    args = parse_args()
    create_output(args.output)
    models = process_rules(args)
    call_activites(args, models)

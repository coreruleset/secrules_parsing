#!/usr/bin/env python3

"""
SecRules CRS Parser
-----------------------------------------------

Copyright (C) 2017 Felipe Zipitria <felipe.zipitria@owasp.org>

This program is free software; you can redistribute it and/or
modify it under the terms of the Apache License 2.0.

"""

import sys
import argparse
import json
from secrules_parsing.parser import process_rules, get_correctness, get_rule_regex


def parse_args():
    """Parse our command line arguments"""
    cmdline = argparse.ArgumentParser(description="ModSecurity CRS parser script.")
    cmdline.add_argument(
        "-r",
        "--regex",
        help="Extract regular expressions from rules",
        action="store_true",
    )
    cmdline.add_argument(
        "-c",
        "--correctness",
        help="Check the validity of the syntax",
        action="store_true",
    )
    cmdline.add_argument(
        "-f",
        "--files",
        metavar="FILE",
        required=True,
        nargs="*",
        help="files to read, if empty, stdin is used",
    )
    cmdline.add_argument(
        "-v", "--verbose", help="Print verbose messages", action="store_true"
    )
    cmdline.add_argument(
        "-d", "--debug", help="You don't want to do this!", action="store_true"
    )
    cmdline.add_argument(
        "-o", "--output", metavar="FILE", help="Output results to file"
    )
    cmdline.add_argument(
        "--output-type",
        default="plain",
        choices=["plain", "github"],
        help='Format results for this output. Default "plain".',
    )
    myargs = cmdline.parse_args()
    return myargs


def call_activites(args, models):
    """For firing actions based on CLI args"""
    exitcode = 0
    if args.correctness:
        exitcode = get_correctness(args.files, args.output_type, models)
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
    return exitcode


def create_output(output_loc):
    """If output is specified we modify running"""
    if output_loc is not None:
        sys.stdout = open(output_loc, "w")


def run():
    """Runs the example parser"""
    args = parse_args()
    create_output(args.output)
    models = process_rules(args.files, args.verbose, args.debug)
    exitcode = call_activites(args, models)
    sys.exit(exitcode)


if __name__ == "__main__":
    run()

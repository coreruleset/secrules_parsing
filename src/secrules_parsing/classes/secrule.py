from pprint import pprint


class RuleFormatException(Exception):
    def __init__(self, message):
        self.message = message


class SecRule(object):
    """
    'SecRule' variables+=Variable['|']'"' operator=Operator '"' '"'? actions+=Action[',']? '"'?;
    """

    def __init__(self, parent, variables, operator, actions):
        self.parent = parent
        self.variables = variables
        self.operator = operator
        self.actions = actions

        self.id = None
        self.parent_id = None
        self.capture = False
        self.log = False
        # If rule is chained, the chained == True
        # and the chain list has the parent rules
        self.chain = []
        self.chained = False

        for action in self.actions:
            if action.name == "chain":
                self.chained = True
            if action.name == "id":
                self.id = action.value
            if action.name == "capture":
                self.capture = True
            if action.name == "log":
                self.log = True

        if self.__class__.__name__ == "SecRule":
            print("This is a SecRule")
            if self.id is None:
                print("This secrule has no ID, must be part of a chain")
                # Check if previous rules are chained and add values
                previous_rules = reversed(self.parent.rules[:-1])
                for prev_rule in previous_rules:
                    pprint(prev_rule)
                    if prev_rule.__class__.__name__ == "SecRule" and prev_rule.chained == True:
                        print("Good, Parent secrule is chained")
                        self.chain.append(prev_rule)
                        if prev_rule.id:
                            self.parent_id = prev_rule.id
                            break
                    else:
                        # parent must be part of a chain also
                        raise RuleFormatException("SecRule has no id and is no chained")
        elif self.__class__.__name__ == "SecAction":
            if self.id is None:
                raise RuleFormatException("SecAction without id")

        # TODO: more semantic checks are neccessary here

    def __repr__(self):
        if self.chained and self.id is None:
            repr = "{indent}This SecRule is the {number} chained from {id}".format(
                indent=self.indent(),
                number=self.indentation_level(),
                id=self.get_parent_id(),
            )
        else:
            repr = "This is SecRule {id}".format(id=self.get_id())

        return repr

    def indentation_level(self):
        return len(self.chain)

    def indent(self):
        return "    " * self.indentation_level()

    def actions_indent(self):
        return self.indent() + "    "

    def get_id(self):
        """
        Id makes sense only on SecRule and maybe chained rules
        :return: Id
        :raise: Unsupported ID for this type of Rules
        """
        if (
            self.__class__.__name__ == "SecRule"
            or self.__class__.__name__ == "SecAction"
        ):
            if self.id is not None:
                return self.id
            else:
                # This should be a chained tule
                self.get_parent_id()
        else:
            raise ("Unsupported ID for this type of Rules")

    def get_parent_id(self):
        print("Getting parent_id")
        if len(self.chain) > 0:
            for i, t in enumerate(self.chain):
                print(i)
                print(t.id)
            return self.chain[len(self.chain) - 1].id
        return 0

    def print_ordered(self):
        """
        From: https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.2/dev/CONTRIBUTING.md, order is:
            id
            phase
            disruptive-action
            status
            capture
            t:xxx
            log
            nolog
            auditlog
            noauditlog
            msg
            logdata
            tag
            sanitiseArg
            sanitiseRequestHeader
            sanitiseMatched
            sanitiseMatchedBytes
            ctl
            setenv
            ver
            severity
            setvar
            expirevar
            chain
            skip
            skipAfter

        :return:
        """
        if self.__class__.__name__ == "SecRule":
            variables = "|".join(map(repr, self.variables))
            actions = ",\\\n".join(map(repr, self.actions))
            output = '{indent}SecRule "{variables}" "{operator}" \\\n{actions_indent}"{actions}"{newline}'.format(
                variables=variables,
                operator=self.operator,
                actions=actions,
                indent=self.indent(),
                actions_indent=self.actions_indent(),
                newline="" if self.chained else "\n",
            )
            print(output)
        else:
            print("No SecRule")

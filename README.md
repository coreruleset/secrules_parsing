# OWASP CRS Rules parser

Incomplete parser model and sample application for parsing [Core Rule Set](https://github.com/coreruleset/coreruleset/) written in the ModSecurity DSL SecRule language. It uses the python library [textX](http://www.igordejanovic.net/textX/) for parsing.

## How to use it (CLI):

1. Install dependencies
    Dependencies can be installed system-wide, or just for your user (using `--user`).

    System-wide:
    ```shell
    sudo pip install secrules-parsing
    ```
    User:
    ```shell
    pip install --user secrules-parsing
    ```

2. Execute `secrules-parser` specifying the location of the files you want to scan using the -f/--files argument. This takes wildcards or individual files.
   `$ secrules-parser -c -f /owasp-crs/rules/*.conf`

3. Add flags to accomplish needed tasks:

 - -h, --help:
    * *Description:* show the help message and exit
    * *Example:* `$ secrules-parser -h`

 - -r, --regex:
    * *Description:* Extract regular expressions from rules file
    * *Example:*
    ```
    $ secrules-parser --regex -f /owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
    {"/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf": [{"920100": ["^(?i:(?:[a-z]{3,10}\\s+(?:\\w{3,7}?://[\\w\\-\\./]*(?::\\d+)?)?/[^?#]*(?:\\?[^#\\s]*)?(?:#[\\S]*)?|connect (?:\\d{1,3}\\.){3}\\d{1,3}\\.?(?::\\d+)?|options \\*)\\s+[\\w\\./]+|get /[^?#]*(?:\\?[^#\\s]*)?(?:#[\\S]*)?)$"]}, {"920120": ["(?<!&(?:[aAoOuUyY]uml)|&(?:[aAeEiIoOuU]circ)|&(?:[eEiIoOuUyY]acute)|&(?:[aAeEiIoOuU]grave)|&(?:[cC]cedil)|&(?:[aAnNoO]tilde)|&(?:amp)|&(?:apos));|['\\\"=]"]}, {"920160": ["^\\d+$"]}, {"920170": ["^(?:GET|HEAD)$"]}, {"920171": ["^(?:GET|HEAD)$"]}, {"920180": ["^POST$"]}, {"920190": ["(\\d+)\\-(\\d+)\\,"]}, {"920210": ["\\b(?:keep-alive|close),\\s?(?:keep-alive|close)\\b"]}, {"920220": ["\\%(?:(?!$|\\W)|[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})"]}, {"920240": ["^(?:application\\/x-www-form-urlencoded|text\\/xml)(?:;(?:\\s?charset\\s?=\\s?[\\w\\d\\-]{1,18})?)??$"]}, {"920260": ["\\%u[fF]{2}[0-9a-fA-F]{2}"]}, {"920290": ["^$"]}, {"920310": ["^$"]}, {"920311": ["^$"]}, {"920330": ["^$"]}, {"920340": ["^0$"]}, {"920350": ["^[\\d.:]+$"]}, {"920420": ["^(?:GET|HEAD|PROPFIND|OPTIONS)$"]}, {"920440": ["\\.(.*)$"]}, {"920450": ["^.*$"]}, {"920200": ["^bytes=(?:(?:\\d+)?\\-(?:\\d+)?\\s*,?\\s*){6}"]}, {"920230": ["\\%((?!$|\\W)|[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})"]}, {"920121": ["['\\\";=]"]}, {"920460": ["(?<!\\Q\\\\\\E)\\Q\\\\\\E[cdeghijklmpqwxyz123456789]"]}]}
    ```

 * -c, --correctness:
    * *Description:* Check the validity of the syntax
    * *Example:*
    ```
    $ secrules-parser -c -f /owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
    Syntax OK: ../../../rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
    ```

 * -v, --verbose
    * *Description:* Print verbose messages
    * *Example:*
    ```
    $ secrules-parser -c -v -f /owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
    ...
    ```

 * -o FILE, --output FILE
    * *Description:* Output results to file
    * *Example:*
    ```
    $ secrules-parser -c -o out.json -f /owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf    
    ```

 * --output-type github | plain
    * *Description:* Desired output format. Useful if running from Github Actions and you want annotated output
    * *Example:*
    ```
    $ secrules-parser -c --output-type github -f /owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
    ```

## How to use it (API):

### process_rules(list files)
Takes a list of file path's and returns models
```python
import glob
import os
from secrules_parsing import parser

# Extract all of our pathing
files = glob.glob("../../rules/*.conf")
# Pass absolute paths because of module location
files = [os.path.abspath(path) for path in files]
models = parser.process_rules(files)
```

### get_correctness(list files, list models)
```python
import glob
import os
from secrules_parsing import parser

# Extract all of our pathing
files = glob.glob("../../rules/*.conf")
# Pass absolute paths because of module location
files = [os.path.abspath(path) for path in files]
models = parser.process_rules(files)
parser.get_correctness(files, models)
```

## Development

If you want to modify this module, follow these steps:
1. Clone this repository: `git clone git@github.com:coreruleset/secrules_parsing.git`
1. Do not forget to install dependencies using [poetry](https://python-poetry.org/docs/): `poetry install` first!
1. Edit and change the files you want.
1. Write tests! Tests are in the `tests` subdirectory
1. Create a PR [here](https://github.com/coreruleset/secrules_parsing/compare), and ask for review!

## Misc

To visualize the syntax tree, use:

```
textx visualize secrules.tx
dot -Tpng -O secrules.tx.dot
```

Then review the generated PNG modsec.tx.dot.png!

Please file an [issue](https://github.com/coreruleset/secrules_parsing/issues) if you find a bug or you want some feature added.

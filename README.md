# OWASP CRS Rules parser

Incomplete parser model and sample application for parsing [Core Rule Set  rules](https://github.com/SpiderLabs/owasp-modsecurity-crs/) written in the SecRules language. It uses the python library [textX](http://www.igordejanovic.net/textX/) for parsing.

How to use it (CLI):

1. Install dependencies
    Dependencies can be installed system-wide, or just for your user (using `--user`).

    System-wide:
    ```
    sudo pip install -r requirements.txt
    ```
    User:
    ```
    pip install --user -r requirements.txt
    ```
1. Execute `./secrules_parser.py` specifying the location of the files you want to scan using the -f/--files argument. This takes wildcards or individual files.

   `$ python secrules_parser.py -f /owasp-crs/rules/*.conf`

3. Add flags to accomplish needed tasks:


 * -h, --help:
  * *Description:* show the help message and exit
  * *Example:* `$ python secrules_parser.py -h`
  
 * -r, --regex:
  * *Description:* Extract regular expressions from rules file
  * *Example:*

  ```
  $ python secrules_parser.py --regex /owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf

  {"/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf": [{"920100": ["^(?i:(?:[a-z]{3,10}\\s+(?:\\w{3,7}?://[\\w\\-\\./]*(?::\\d+)?)?/[^?#]*(?:\\?[^#\\s]*)?(?:#[\\S]*)?|connect (?:\\d{1,3}\\.){3}\\d{1,3}\\.?(?::\\d+)?|options \\*)\\s+[\\w\\./]+|get /[^?#]*(?:\\?[^#\\s]*)?(?:#[\\S]*)?)$"]}, {"920120": ["(?<!&(?:[aAoOuUyY]uml)|&(?:[aAeEiIoOuU]circ)|&(?:[eEiIoOuUyY]acute)|&(?:[aAeEiIoOuU]grave)|&(?:[cC]cedil)|&(?:[aAnNoO]tilde)|&(?:amp)|&(?:apos));|['\\\"=]"]}, {"920160": ["^\\d+$"]}, {"920170": ["^(?:GET|HEAD)$"]}, {"920171": ["^(?:GET|HEAD)$"]}, {"920180": ["^POST$"]}, {"920190": ["(\\d+)\\-(\\d+)\\,"]}, {"920210": ["\\b(?:keep-alive|close),\\s?(?:keep-alive|close)\\b"]}, {"920220": ["\\%(?:(?!$|\\W)|[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})"]}, {"920240": ["^(?:application\\/x-www-form-urlencoded|text\\/xml)(?:;(?:\\s?charset\\s?=\\s?[\\w\\d\\-]{1,18})?)??$"]}, {"920260": ["\\%u[fF]{2}[0-9a-fA-F]{2}"]}, {"920290": ["^$"]}, {"920310": ["^$"]}, {"920311": ["^$"]}, {"920330": ["^$"]}, {"920340": ["^0$"]}, {"920350": ["^[\\d.:]+$"]}, {"920420": ["^(?:GET|HEAD|PROPFIND|OPTIONS)$"]}, {"920440": ["\\.(.*)$"]}, {"920450": ["^.*$"]}, {"920200": ["^bytes=(?:(?:\\d+)?\\-(?:\\d+)?\\s*,?\\s*){6}"]}, {"920230": ["\\%((?!$|\\W)|[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})"]}, {"920121": ["['\\\";=]"]}, {"920460": ["(?<!\\Q\\\\\\E)\\Q\\\\\\E[cdeghijklmpqwxyz123456789]"]}]}
  ```

* -c, --correctness:
  * *Description:* Check the validity of the syntax
  * *Example:*

  ```
  $ python secrules_parser.py -c -f /owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf

  Syntax OK: ../../../rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
  ```

* -v, --verbose
 * *Description:* Print verbose messages
 * *Example:*

 ```
 $ python secrules_parser.py -c -v -f /owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf

 ...
 ```

* -o FILE, --output FILE
 * *Description:* Output results to file
 * *Example:*
 ```
 $ python secrules_parser.py -c -o out.json -f /owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf    
 ```

Please file an [issue](https://github.com/CRS-support/secrules-parser/issues) if you find a bug or you want some feature added.

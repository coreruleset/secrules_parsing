class ParserException(Exception):
    def __init__(self, file="", line=0, column=0, message=""):
        self.file = file
        self.line = line
        self.column = column
        self.message = message

    # def __repr__(self):
    #     print(
    #         f"Syntax invalid: Syntax error at line {self.line}, column {self.colunm}: {self.message}"
    #     )

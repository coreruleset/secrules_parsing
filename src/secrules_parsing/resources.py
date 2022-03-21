from importlib import resources


def get_model():
    """Get path to SecRule Model file

    Returns
    -------
    pathlib.PosixPath
        Path to file.

    """
    with resources.path("secrules_parsing.model", "secrules.tx") as f:
        data_file_path = f
    return data_file_path

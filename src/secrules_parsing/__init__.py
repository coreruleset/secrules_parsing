from importlib.metadata import PackageNotFoundError, version


try:
    __version__ = version(__package__)
except PackageNotFoundError:
    # imported from a source tree without being installed (PYTHONPATH=src)
    __version__ = "0.0.0+unknown"

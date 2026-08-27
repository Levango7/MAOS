"""MAOP namespace package — enterprise extension.

This file makes ``maop`` a namespace package so that both the main
``maop`` wheel and the ``maop-enterprise`` wheel can contribute
subpackages under the ``maop`` namespace without conflicting.

pkgutil.extend_path ensures that when both wheels are installed,
Python finds subpackages from both installation directories.
"""
__path__ = __import__('pkgutil').extend_path(__path__, __name__)

# Preserve __version__ from the main maop package metadata
# (so that maop.__version__ is available regardless of install order)
try:
    from importlib.metadata import version as _version
    __version__ = _version("maop")
except Exception:
    pass

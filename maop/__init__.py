"""MAOP namespace package — enterprise extension.

This file makes ``maop`` a namespace package so that both the main
``maop`` wheel and the ``maop-enterprise`` wheel can contribute
subpackages under the ``maop`` namespace without conflicting.

pkgutil.extend_path ensures that when both wheels are installed,
Python finds subpackages from both installation directories.
"""
__path__ = __import__('pkgutil').extend_path(__path__, __name__)
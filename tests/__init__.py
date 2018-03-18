import logging
import os.path
import sys

if sys.version_info[:2] <= (2, 6):
    sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                    'vendor'))

try:
    import unittest2 as unittest
except ImportError:
    import unittest


logging.basicConfig(format='%(levelname)s:%(funcName)s:%(message)s',
                    level=logging.DEBUG)

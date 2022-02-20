"""
Researchmap API wrapper

This is a wrapper for the Researchmap API. It provides a simple interface to
make requests to the API and return the results as a dictionary.

The API documentation can be found at https://researchmap.jp/outline/v2api/v2API.pdf
:copyright: (c) 2022 by the authors and contributors (see AUTHORS).
:license: MIT, see LICENSE for more details.
"""
__title__ = 'researchmap'
__author__ = 'RTa-technology'
__license__ = 'MIT'
__copyright__ = 'Copyright 2022 by the authors and contributors (see AUTHORS)'
__version__ = '0.1.0'

__path__ = __import__('pkgutil').extend_path(__path__, __name__)

from .core import Adapter, AiohttpAdapter, RequestsAdapter
from .adapter import Wrapper

__all__ = [
  'Wrapper',
  'Adapter',
  'AiohttpAdapter',
  'RequestsAdapter'
]

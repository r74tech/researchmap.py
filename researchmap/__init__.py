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
__version__ = '0.0.1'

__path__ = __import__('pkgutil').extend_path(__path__, __name__)

from .adapter import Auth, Authentication, Adapter, AiohttpAdapter, RequestsAdapter
from .wrapper import Wrapper

from .errors import (UnsupportedResponseType, UnauthorizedClient, AccessDenied, InvalidClient, InvalidScope,
                     InvalidGrant, UnsupportedGrantType, InvalidVersion, ParseError, InvalidNonce,
                     InvalidRequest, InvalidToken, MalformedToken, InsufficientScope, InvalidIP,
                     Forbidden, NotFound, MethodNotAllowed, MaxSearchResult, DatabaseError,
                     ServerError, InternalServerError, HTTPException)

__all__ = [
  'Wrapper',
  'Adapter',
  'Auth',
  'Authentication',
  'AiohttpAdapter',
  'RequestsAdapter'
]

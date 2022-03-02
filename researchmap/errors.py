import aiohttp
import requests

__all__ = [
  'ResearchmapException',
  'HTTPException',
  "UnsupportedResponseType",
  "UnauthorizedClient",
  "AccessDenied",
  "InvalidClient",
  "InvalidScope",
  "InvalidGrant",
  "UnsupportedGrantType",
  "InvalidVersion",
  "ParseError",
  "InvalidNonce",
  "InvalidRequest",
  "InvalidToken",
  "MalformedToken",
  "InsufficientScope",
  "InvalidIP",
  "Forbidden",
  "NotFound",
  "MethodNotAllowed",
  "MaxSearchResult",
  "DatabaseError",
  "ServerError",
  "InternalServerError",
]


class ResearchmapException(Exception):
  pass


class HTTPException(ResearchmapException):
  """Exception raised when an HTTP request fails.

  Attributes
  ------------
  response: Union[:class:`aiohttp.ClientResponse`, :class:`requests.Response`]
      If you are using the RequestsAdapter,
      :class:`requests.Response`.
      If you are using the AiohttpAdapter,
      :class:`aiohttp.ClientResponse`.
  message: :class:`str`
      The Messages returned by Researchmap API.
  status: :class:`int`
      The status code of the HTTP request.
  """

  def __init__(self, response, messega, *, error: str = None) -> None:
    self.response = response
    if error is not None:
      self.error = f"<{error}>"
    self.message = messega or 'No error message was sent from the Researchmap API.'
    if isinstance(response, aiohttp.ClientResponse):
      self.status = response.status
    elif isinstance(response, requests.Response):
      self.status = response.status_code

    super().__init__(f'{self.status} {response.reason}{self.error}: {self.message}')


class UnsupportedResponseType(HTTPException):
  """Exception raised when the response type is not supported.
  Subclass of :exc:`HTTPException`

  .. note::

    Researchmap API v2 returns this error when the response type is not supported.
  """
  pass


class UnauthorizedClient(HTTPException):
  """Exception raised when the client is not authorized.
  Subclass of :exc:`HTTPException`

  .. note::

    Researchmap API v2 returns this error when the client is not authorized in the current way.

    -> Check if the client ID is correct and if the signature information by JWT is correct.

    -> Also, this message will appear if you execute a Flow that is not allowed in grant_type when creating the client ID.
  """
  pass


class AccessDenied(HTTPException):
  """Exception raised when denied access.
  Subclass of :exc:`HTTPException`
  """
  pass


class InvalidClient(HTTPException):
  """Exception raised when the client is invalid.
  Subclass of :exc:`HTTPException`
  """
  pass


class InvalidScope(HTTPException):
  """Exception raised when the scope is invalid
  Subclass of :exc:`HTTPException`
  """
  pass


class InvalidGrant(HTTPException):
  """Exception raised when the grant is invalid.
  Subclass of :exc:`HTTPException`
  """
  pass


class UnsupportedGrantType(HTTPException):
  """Exception raised when the type of grant is not supported.
  Subclass of :exc:`HTTPException`
  """
  pass


class InvalidVersion(HTTPException):
  """Exception raised when the version is invalid.
  Subclass of :exc:`HTTPException`
  """
  pass


class ParseError(HTTPException):
  """Exception raised when error occurs during parsing.
  Subclass of :exc:`HTTPException`
  """
  pass


class InvalidNonce(HTTPException):
  """Exception raised when the notce is invalid.
  Subclass of :exc:`HTTPException`
  """
  pass


class InvalidRequest(HTTPException):
  """Exception raised when the request is invalid.
  Subclass of :exc:`HTTPException`
  """
  pass


class InvalidToken(HTTPException):
  """Exception raised when the token is invalid.
  Subclass of :exc:`HTTPException`
  """
  pass


class MalformedToken(HTTPException):
  """Exception raised when the token is malformed.
  Subclass of :exc:`HTTPException`
  """
  pass


class InsufficientScope(HTTPException):
  """Exception raised when the scope of the request is insufficient.
  Subclass of :exc:`HTTPException`
  """
  pass


class InvalidIP(HTTPException):
  """Exception raised when the ip is invalid.
  Subclass of :exc:`HTTPException`
  """
  pass


class Forbidden(HTTPException):
  """Authorization failed. Please supply a valid auth_key parameter.
  Subclass of :exc:`HTTPException`
  """
  pass


class NotFound(HTTPException):
  """The requested resource could not be found.
  Subclass of :exc:`HTTPException`
  """
  pass


class MethodNotAllowed(HTTPException):
  """The requested method is not allowed.
  Subclass of :exc:`HTTPException`
  """
  pass


class MaxSearchResult(HTTPException):
  """The requested limit is too large.
  Subclass of :exc:`HTTPException`
  """
  pass


class DatabaseError(HTTPException):
  """The database is unavailable.
  Subclass of :exc:`HTTPException`
  """
  pass


class ServerError(HTTPException):
  """The server is unavailable.
  Subclass of :exc:`HTTPException`
  """
  pass


class InternalServerError(HTTPException):
  """	Internal error
  Subclass of :exc:`HTTPException`
  """
  pass

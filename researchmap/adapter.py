import json
from abc import ABCMeta, abstractmethod
from typing import List, Optional, Union
import jwt
import aiohttp
import datetime
import requests
import re
import urllib.parse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import pprint

from .errors import (UnsupportedResponseType, UnauthorizedClient, AccessDenied, InvalidClient, InvalidScope,
                     InvalidGrant, UnsupportedGrantType, InvalidVersion, ParseError, InvalidNonce,
                     InvalidRequest, InvalidToken, MalformedToken, InsufficientScope, InvalidIP,
                     Forbidden, NotFound, MethodNotAllowed, MaxSearchResult, DatabaseError,
                     ServerError, InternalServerError, HTTPException)

__all__ = ['Authentication', 'Auth', 'Adapter', 'RequestsAdapter', 'AiohttpAdapter']


class Authentication(metaclass=ABCMeta):
  def __init__(self, client_id, client_secret, scope, *, iat: int = 30, exp: int = 30, sub="0", trial: bool = False):
    self.trial = trial
    self.endpoint = 'https://api.researchmap.jp/oauth2/token' if not self.trial else 'https://api-trial.researchmap.jp/oauth2/token'
    self.version = "2"
    self.grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    self.algorithm = "RS256"
    self.client_id = client_id
    self.client_secret = client_secret
    self.scope = scope
    self.iat = iat
    self.exp = exp
    self.sub = sub
    self.now = datetime.datetime.now(datetime.timezone.utc)

  @abstractmethod
  def gen_jwt(self) -> bytes:
    raise NotImplementedError()

  @abstractmethod
  def gen_pubkey(self) -> bytes:
    raise NotImplementedError()

  @abstractmethod
  def is_authorization(self, _jwt: str, client_public: str) -> bool:
    raise NotImplementedError()

  @abstractmethod
  def get_access_token_response(self, jwt: str, **kwargs) -> Optional[Union[list, dict]]:
    raise NotImplementedError()

  @abstractmethod
  def get_access_token(self, *, access_token_response: str) -> str:
    raise NotImplementedError()

  @abstractmethod
  def get_usage(self) -> dict:
    raise NotImplementedError()

  def _check_status(self, status_code, response, data) -> Union[dict, list]:
    if 200 <= status_code < 300:
      return data
    error_messages = data.get('error', '') if data else ''
    message = data.get('error_description', '') if data else ''
    if status_code == 302 and error_messages == 'unsupported_response_type':
      raise UnsupportedResponseType(response, message)
    elif status_code == 400 and error_messages == 'unauthorized_client':
      raise UnauthorizedClient(response, message, error="unauthorized_client")
    elif status_code == 400 and error_messages == 'access_denied':
      raise AccessDenied(response, message, error="access_denied")
    elif status_code == 400 and error_messages == 'invalid_client':
      raise InvalidClient(response, message, error="invalid_client")
    elif status_code == 400 and error_messages == 'invalid_scope':
      raise InvalidScope(response, message, error="invalid_scope")
    elif status_code == 400 and error_messages == 'invalid_grant':
      raise InvalidGrant(response, message, error="invalid_grant")
    elif status_code == 400 and error_messages == 'unsupported_grant_type':
      raise UnsupportedGrantType(response, message, error="unsupported_grant_type")
    elif status_code == 400 and error_messages == 'invalid_version':
      raise InvalidVersion(response, message, error="invalid_version")
    elif status_code == 400 and error_messages == 'parse_error':
      raise ParseError(response, message, error="parse_error")
    elif status_code == 400 and error_messages == 'invalid_nonce':
      raise InvalidNonce(response, message, error="invalid_nonce")
    elif (status_code == 400 or status_code == 405) and error_messages == 'invalid_request':
      raise InvalidRequest(response, message, error="invalid_request")
    elif status_code == 401 and error_messages == 'invalid_token':
      raise InvalidToken(response, message, error="invalid_token")
    elif status_code == 401 and error_messages == 'malformed_token':
      raise MalformedToken(response, message, error="malformed_token")
    elif status_code == 401 and error_messages == 'insufficient_scope':
      raise InsufficientScope(response, message, error="insufficient_scope")
    elif status_code == 401 and error_messages == 'invalid_ip':
      raise InvalidIP(response, message, error="invalid_ip")
    elif status_code == 403:
      raise Forbidden(response, message, error="forbidden")
    elif status_code == 404:
      raise NotFound(response, message, error="not_found")
    elif status_code == 405 and error_messages == 'method_not_allowed':
      raise MethodNotAllowed(response, message, error="method_not_allowed")
    elif status_code == 416 and error_messages == 'max_search_result':
      raise MaxSearchResult(response, message, error="max_search_result")
    elif status_code == 500 and error_messages == 'database_error':
      raise DatabaseError(response, message, error="database_error")
    elif status_code == 500 and error_messages == 'server_error':
      raise ServerError(response, message, error="server_error")
    elif 500 <= status_code < 600:
      raise InternalServerError(response, message)
    else:
      raise HTTPException(response, message)


class Auth(Authentication):
  """Researchmap authentication interface.

  Parameters
  ----------
  client_id: :class:`str`
    Client ID.
  client_secret: :class:`bytes`
    Client secret key.

  Keyword Arguments
  -----------------
  iat: :class:`int`
    Issued at [sec].
  exp: :class:`int`
    Expire at [sec].
  sub: :class:`int`
    Subject.
  trial: :class:`bool`
    Trial mode.
  """

  @property
  def is_trial(self) -> bool:
    """Get trial mode.

    Returns
    -------
    :class:`bool`
      Trial mode.
    """
    return self.trial

  @property
  def time_now(self) -> datetime.datetime:
    """Get current time [aware].

    Returns
    -------
    :class:`datetime.datetime`
      Current time of UTC.
    """
    return self.now

  @property
  def time_iat(self) -> datetime.datetime:
    """Get issued at time [aware].

    Returns
    -------
    :class:`datetime.datetime`
      Issued at time of UTC.
    """
    return self.now - datetime.timedelta(seconds=self.iat)

  @property
  def time_exp(self) -> datetime.datetime:
    """Get expire at time [aware].

    Returns
    -------
    :class:`datetime.datetime`
      Expire at time of UTC.
    """
    return self.now + datetime.timedelta(seconds=self.exp)

  @property
  def token(self) -> str:
    """Get token.

    Returns
    -------
    :class:`str`
      Token.

    Raises
    ------
    :exc:`InvalidToken`
      Invalid token.
    :class:`json.JSONDecodeError`
      JSON decode error.
    :class:`requests.exceptions.HTTPError`
      HTTP error.
    """
    return self.get_access_token()

  def gen_jwt(self, *, exp: int = None, iat: int = None, sub: str = None) -> bytes:
    """Generate JWT.

    Keyword Arguments
    -----------------
    exp: :class:`int`
      Expire at [sec].
    iat: :class:`int`
      Issued at [sec].
    sub: :class:`int`
      Subject.

    Returns
    -------
    :class:`bytes`
      JWT.
    """
    if exp is None:
      exp = self.exp
    if iat is None:
      iat = self.iat
    if sub is None:
      sub = self.sub

    payload = {
      "iss": self.client_id,
      "aud": self.endpoint,
      "sub": sub,
      "iat": self.now - datetime.timedelta(seconds=iat),
      "exp": self.now + datetime.timedelta(seconds=exp),
    }
    _jwt = jwt.encode(payload, self.client_secret,
                      algorithm=self.algorithm)
    return _jwt

  def gen_pubkey(self, *, client_secret: str = None) -> bytes:
    """
    Generate public key.

    Keyword Arguments
    -----------------
    client_secret: :class:`str`
      Client secret key.

    Returns
    -------
    :class:`bytes`
       Client public key.
    """
    if client_secret is None:
      client_secret = self.client_secret

    privkey = serialization.load_pem_private_key(
      client_secret,
      password=None,
      backend=default_backend()
    )
    pubkey = privkey.public_key()
    client_public = pubkey.public_bytes(
      serialization.Encoding.PEM,
      serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return client_public

  def is_authorization(self, *, _jwt: str = None, client_public: str = None) -> bool:
    """Check authorization.

    Keyword Arguments
    -----------------
    _jwt: :class:`str`
      JWT.
    client_public: :class:`str`
      Client public key.

    Returns
    -------
    :class:`bool`
      True if authorization.

    Raises
    ------
    :class:`jwt.InvalidTokenError`
      Invalid JWT.

    """
    if _jwt is None:
      _jwt = self.gen_jwt()
    if client_public is None:
      client_public = self.gen_pubkey()
    try:
      decoded_jwt = jwt.decode(_jwt, key=client_public,
                               audience=self.endpoint, algorithms=self.algorithm)
      if decoded_jwt['iss'] == self.client_id and decoded_jwt['sub'] == self.sub and decoded_jwt[
        'aud'] == self.endpoint:
        return True
    except:
      print("The signature of JWT cannot be verified.")
      return False

  def get_access_token_response(self, *, _jwt: bytes = None, **kwargs) -> Optional[Union[list, dict]]:
    """Get access token.

    Keyword Arguments
    ----------
    _jwt: :class:`bytes`
      JWT.

    Returns
    -------
    Optional[Union[:class:`list`, :class:`dict`]]
      Access token.

    Raises
    ------
    :exc:`HTTPException`
      An unknown HTTP related error occurred, usually when it isn’t 200 or the known incorrect credentials passing status code.
    """
    if _jwt is None:
      _jwt = self.gen_jwt()
    headers = {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
    params = {
      'grant_type': self.grant_type,
      'assertion': _jwt,
      'scope': self.scope,
      'version': self.version
    }
    payload = urllib.parse.urlencode(params)
    if self.is_authorization():
      req_access_token = requests.post(url=self.endpoint, headers=headers, data=payload)
      try:
        data = req_access_token.json()
      except json.JSONDecodeError:
        redata = re.sub('[\r\n]+$', ' ', req_access_token.content.decode(req_access_token.encoding))
        data = {}
        data["error"] = re.search("<h1>(.+)</h1>", redata).groups()[0].lower()
      return self._check_status(req_access_token.status_code, req_access_token, data)
    else:
      print("Access Token is not valid")

  def get_access_token(self, *, access_token_response: Optional[Union[list, dict]] = None) -> str:
    """Get access token.

    Keyword Arguments
    ----------
    access_token_response: :class: Optional[Union[:class:`list`, :class:`dict`]]
      Access token response.

    Returns
    -------
    :class:`str`
      Access token.

    Raises
    ------
    :class:`TypeError`
      The type of the argument is not correct.
    :exc:`HTTPException`
      An unknown HTTP related error occurred, usually when it isn’t 200 or the known incorrect credentials passing status code.
    :exc:`InvalidToken`
      Invalid token.
    """
    if access_token_response is None:
      access_token_response = self.get_access_token_response()
    return access_token_response['access_token']

  def get_usage(self) -> None:
    return None


class Adapter(metaclass=ABCMeta):
  def __init__(self, authentication_key: str, trial: bool = False) -> None:
    self.trial = trial
    self.base_url = 'https://api.researchmap.jp/{permalink}/{archivement_type}?{query}' if not self.trial \
      else 'https://api-trial.researchmap.jp/{permalink}/{archivement_type}?{query}'
    self.authentication_key = authentication_key
    self.payload = {}

  @abstractmethod
  def request(self, method: str, permalink: str, *,
              archivement_type: str, payload: dict, **kwargs) -> Optional[Union[list, dict]]:
    raise NotImplementedError()

  @abstractmethod
  def get_bulk(self, params: dict):
    raise NotImplementedError()

  @abstractmethod
  def set_bulk(self, jsondata: dict, params: dict):
    raise NotImplementedError()

  @abstractmethod
  def set_bulk_apply(self, params):
    raise NotImplementedError()
  @abstractmethod
  def get_bulk_results(self, params: dict):
    raise NotImplementedError()

  @abstractmethod
  def search_researcher(self, payload: dict):
    raise NotImplementedError()

  @abstractmethod
  def get_usage(self) -> dict:
    raise NotImplementedError()

  def _check_status(self, status_code, response, data) -> Union[dict, list]:
    if 200 <= status_code < 300:
      return data
    print(data)
    error_messages = data.get('error', '') if data else ''
    message = data.get('error_description', '') if data else ''
    if status_code == 302 and error_messages == 'unsupported_response_type':
      raise UnsupportedResponseType(response, message)
    elif status_code == 400 and error_messages == 'unauthorized_client':
      raise UnauthorizedClient(response, message, error="unauthorized_client")
    elif status_code == 400 and error_messages == 'access_denied':
      raise AccessDenied(response, message, error="access_denied")
    elif status_code == 400 and error_messages == 'invalid_client':
      raise InvalidClient(response, message, error="invalid_client")
    elif status_code == 400 and error_messages == 'invalid_scope':
      raise InvalidScope(response, message, error="invalid_scope")
    elif status_code == 400 and error_messages == 'invalid_grant':
      raise InvalidGrant(response, message, error="invalid_grant")
    elif status_code == 400 and error_messages == 'unsupported_grant_type':
      raise UnsupportedGrantType(response, message, error="unsupported_grant_type")
    elif status_code == 400 and error_messages == 'invalid_version':
      raise InvalidVersion(response, message, error="invalid_version")
    elif status_code == 400 and error_messages == 'parse_error':
      raise ParseError(response, message, error="parse_error")
    elif status_code == 400 and error_messages == 'invalid_nonce':
      raise InvalidNonce(response, message, error="invalid_nonce")
    elif (status_code == 400 or status_code == 405) and error_messages == 'invalid_request':
      raise InvalidRequest(response, message, error="invalid_request")
    elif status_code == 401 and error_messages == 'invalid_token':
      raise InvalidToken(response, message, error="invalid_token")
    elif status_code == 401 and error_messages == 'malformed_token':
      raise MalformedToken(response, message, error="malformed_token")
    elif status_code == 401 and error_messages == 'insufficient_scope':
      raise InsufficientScope(response, message, error="insufficient_scope")
    elif status_code == 401 and error_messages == 'invalid_ip':
      raise InvalidIP(response, message, error="invalid_ip")
    elif status_code == 403:
      raise Forbidden(response, message, error="forbidden")
    elif status_code == 404:
      raise NotFound(response, message, error="not_found")
    elif status_code == 405 and error_messages == 'method_not_allowed':
      raise MethodNotAllowed(response, message, error="method_not_allowed")
    elif status_code == 416 and error_messages == 'max_search_result':
      raise MaxSearchResult(response, message, error="max_search_result")
    elif status_code == 500 and error_messages == 'database_error':
      raise DatabaseError(response, message, error="database_error")
    elif status_code == 500 and error_messages == 'server_error':
      raise ServerError(response, message, error="server_error")
    elif 500 <= status_code < 600:
      raise InternalServerError(response, message)
    else:
      raise HTTPException(response, message)



class RequestsAdapter(Adapter):
  def request(self, method: str, permalink: str, *,
              archivement_type: str = None, query: str = None, params=None, payload=None, jsondata=None, **kwargs) -> Optional[
    Union[list, dict]]:
    if archivement_type is None:
      archivement_type = ""
    if query is None:
      query = ""
    if payload is None:
      payload = {}
    if params is None:
      params = {}
    if jsondata is None:
      jsondata = {}
    headers = {
      'Authorization': 'Bearer {}'.format(self.authentication_key),
      'Accept': 'application/ld+json,application/json;q=0.1',
      'Content-Type': 'application/x-www-form-urlencoded'
    }
    url = self.base_url.format(permalink=permalink, archivement_type=archivement_type, query=query)

    resp = requests.request(method, url, params=params, data=payload, json=jsondata, headers=headers, **kwargs)
    try:
      data = resp.json()
    except jsondata.JSONDecodeError:
      data = resp.content
    return self._check_status(resp.status_code, resp, data)

  def get_bulk(self, params=None) -> Union[list, dict, None]:
    """
    Get bulk data from the API.

    Parameters
    ----------
    params : :class:`dict`
      A dictionary containing the parameters for the request.

    Returns
    -------
    :class:`dict` or :class:`list`
      A dictionary or list containing the data returned by the API.
    """
    if params is None:
      params = {}
    data = self.request('POST', '_bulk', params=params)
    print(data)
    return data

  def set_bulk(self, params=None, jsondata=None) -> Union[list, dict, None]:
    """
    Set bulk data to the API.

    Parameters
    ----------
    params : :class:`dict`
      A dictionary containing the data to be set.
    jsondata

    Returns
    -------
    :class:`dict` or :class:`list`
      A dictionary or list containing the data returned by the API.
    """
    if params is None:
      params = {}
    if jsondata is None:
      jsondata = {}

    data = self.request('POST', '_bulk', params=params, jsondata=jsondata)
    return data


  def set_bulk_apply(self, params=None) -> Union[list, dict, None]:
    """
    Set bulk data to the API.

    Parameters
    ----------
    params : :class:`dict`
      A dictionary containing the data to be set.

    Returns
    -------
    :class:`dict` or :class:`list`
      A dictionary or list containing the data returned by the API.
    """
    if params is None:
      params = {}

    data = self.request('POST', '_bulk', params=params)
    return data

  def get_bulk_results(self, params=None) -> Union[list, dict, None]:
    """
    Get bulk results from the API.

    Parameters
    ----------
    params : :class:`dict`
      A dictionary containing the parameters for the request.

    Returns
    -------
    :class:`dict` or :class:`list`
      A dictionary or list containing the data returned by the API.
    """
    if params is None:
      params = {}
    data = self.request('GET', '_bulk_results', params=params)
    return data

  def search_researcher(self, payload=None) -> Union[list, dict, None]:
    """ Search for researchers.

    Parameters
    ----------
    payload : :class:`dict`
      A dictionary containing the parameters for the request.

    Returns
    -------
    :class:`dict` or :class:`list`
      A dictionary or list containing the data returned by the API.
    """
    if payload is None:
      payload = {}
    data = self.request('GET', 'researchers', payload=payload)
    return data

  def get_researcher_profile(self, permalink, payload=None) -> Union[list, dict, None]:
    """ Get a researcher profile.

    Parameters
    ----------
    permalink : :class:`str`
      The permalink of the researcher.
    payload : :class:`dict`
      A dictionary containing the parameters for the request.

    Returns
    -------
    :class:`dict` or :class:`list`
      A dictionary or list containing the data returned by the API.
    """
    if payload is None:
      payload = {}
    data = self.request('GET', permalink, archivement_type='profile', payload=payload)
    return data

  def get_usage(self) -> None:
    return None


class AiohttpAdapter(Adapter):
  async def request(self, method: str, permalink: str, *,
                    archivement_type: str = "", query: str = "", payload=None, **kwargs) -> Optional[
    Union[list, dict]]:
    if payload is None:
      payload = {}
    payload['auth_key'] = self.authentication_key
    url = self.base_url.format(permalink=permalink, archivement_type=archivement_type, query=query)

    async with aiohttp.request(
        method, url, data=payload, **kwargs) as resp:
      try:
        data = await resp.json(content_type=None)
      except json.JSONDecodeError:
        data = await resp.read()
      status_code = resp.status
    return self._check_status(status_code, resp, data)

  async def get_bulk(self, payload=None) -> Union[list, dict, None]:
    """
    Get bulk data from the API.

    Parameters
    ----------
    payload : :class:`dict`
      A dictionary containing the parameters for the request.

    Returns
    -------
    :class:`dict` or :class:`list`
      A dictionary or list containing the data returned by the API.
    """
    if payload is None:
      payload = {}
    data = await self.request('POST', '/_bulk', payload=payload)
    return data

  async def search_researcher(self, payload=None) -> Union[list, dict, None]:
    """ Search for researchers.

    Parameters
    ----------
    payload : :class:`dict`
      A dictionary containing the parameters for the request.

    Returns
    -------
    :class:`dict` or :class:`list`
      A dictionary or list containing the data returned by the API.
    """
    if payload is None:
      payload = {}
    data = await self.request('POST', '/researchers', payload=payload)
    return data

  async def get_researcher_profile(self, permalink, payload=None) -> Union[list, dict, None]:
    """ Get a researcher profile.

    Parameters
    ----------
    permalink : :class:`str`
      The permalink of the researcher.
    payload : :class:`dict`
      A dictionary containing the parameters for the request.

    Returns
    -------
    :class:`dict` or :class:`list`
      A dictionary or list containing the data returned by the API.
    """
    if payload is None:
      payload = {}
    data = await self.request('POST', permalink, archivement_type='profile', payload=payload)
    return data

  async def get_usage(self) -> None:
    return None

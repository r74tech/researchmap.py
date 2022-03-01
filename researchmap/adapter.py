import json
from abc import ABCMeta, abstractmethod
from typing import List, Optional, Union
import jwt
import aiohttp
import datetime
import requests

import urllib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .errors import (UnsupportedResponseType, UnauthorizedClient, AccessDenied, InvalidClient, InvalidScope,
                     InvalidGrant, UnsupportedGrantType, InvalidVersion, ParseError, InvalidNonce,
                     InvalidRequest, InvalidToken, MalformedToken, InsufficientScope, InvalidIP,
                     Forbidden, NotFound, MethodNotAllowed, MaxSearchResult, DatabaseError,
                     ServerError, InternalServerError, HTTPException)

__all__ = ['Authentication', 'Auth', 'Adapter', 'RequestsAdapter', 'AiohttpAdapter']


class Authentication(metaclass=ABCMeta):
  def __init__(self, client_id, client_secret, scope, *, iat: int = 30, exp: int = 30, sub=0, trial: bool = False):
    self.endpoint = 'https://api.researchmap.jp/oauth2/token'
    self.version = "2"
    self.grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    self.algorithm = "RS256"
    self.client_id = client_id
    self.client_secret = client_secret
    self.scope = scope
    self.iat = iat
    self.exp = exp
    self.sub = sub
    self.trial = trial
    self.now = datetime.datetime.now(datetime.timezone.utc)

  @abstractmethod
  def gen_jwt(self) -> str:
    raise NotImplementedError()

  @abstractmethod
  def gen_pubkey(self) -> str:
    raise NotImplementedError()

  @abstractmethod
  def is_authorization(self, _jwt: str, client_public: str) -> bool:
    raise NotImplementedError()

  @abstractmethod
  def get_access_token(self, jwt: str, **kwargs):
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
  client_secret: :class:`str`
    Client secret.key.

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
  def is_trial(self) -> bool:
    """Get trial mode.

    Returns
    -------
    :class:`bool`
      Trial mode.
    """
    return self.trial

  def gen_jwt(self, *, exp: int = None, iat: int = None, sub: int = None) -> str:
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
    :class:`str`
      jwt auth token.
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

  def gen_pubkey(self, *, client_secret: str = None) -> str:
    """
    Generate public key.

    Keyword Arguments
    -----------------
    client_secret: :class:`str`
      Client secret key.

    Returns
    -------
    :class:`str`
      public key.
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
    """
    if _jwt is None:
      _jwt = self.gen_jwt()
    if client_public is None:
      client_public = self.gen_pubkey()
    try:
      decoded_jwt = jwt.decode(_jwt, key=client_public,
                               audience=self.endpoint, algorithms=self.algorithm)
      if decoded_jwt['iss'] == self.client_id and decoded_jwt['sub'] == self.sub and decoded_jwt[
        'aud'] == self.endpoint and decoded_jwt['iat'] == int(self.time_iat.timestamp()) and decoded_jwt[
        'exp'] == int(self.time_exp.timestamp()):
        return True
    except:
      return False

  def get_access_token(self, *, _jwt: str = None, **kwargs) -> Optional[Union[list, dict]]:
    """Get access token.

    Keyword Arguments
    ----------
    _jwt: :class:`str`
      JWT token.

    Returns
    -------
    Optional[Union[:class:`list`, :class:`dict`]]
      Access token.

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
    data = urllib.parse.urlencode(params)
    if self.is_authorization():
      req_access_token = requests.post(url=self.endpoint, headers=headers, data=data)
      try:
        data = req_access_token.json()
      except json.JSONDecodeError:
        data = req_access_token.content
      return self._check_status(req_access_token.status_code, req_access_token, data)
    else:
      print("Access Token is not valid")

  def get_usage(self) -> None:
    return None


class Adapter(metaclass=ABCMeta):
  def __init__(self, authentication_key: str) -> None:
    self.base_url = 'https://api.researchmap.jp/{permalink}/{archivement_type}?{query}'
    self.authentication_key = authentication_key
    self.payload = {}

  @abstractmethod
  def request(self, method: str, permalink: str, *,
              archivement_type: str, payload: dict, **kwargs) -> Optional[Union[list, dict]]:
    raise NotImplementedError()

  @abstractmethod
  def get_bulk(self, payload: dict):
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
              archivement_type: str = "", query: str = "", payload=None, **kwargs) -> Optional[Union[list, dict]]:

    if payload is None:
      payload = {}
    headers = {
      'Authorization': 'Bearer {}'.format(self.authentication_key),
      'Accept': 'application/ld+json,application/json;q=0.1',
      'Content-Type': 'application/x-www-form-urlencoded'
    }
    url = self.base_url.format(permalink=permalink, archivement_type=archivement_type, query=query)
    payload = urllib.parse.urlencode(payload)
    resp = requests.request(method, url, headers=headers, data=payload, **kwargs)
    try:
      data = resp.json()
    except json.JSONDecodeError:
      data = resp.content
    return self._check_status(resp.status_code, resp, data)

  def get_bulk(self, payload=None) -> Union[list, dict, None]:
    if payload is None:
      payload = {}
    data = self.request('GET', '/_bulk', payload=payload)
    return data

  def search_researcher(self, payload=None) -> Union[list, dict, None]:
    if payload is None:
      payload = {}
    data = self.request('GET', '/researchers', payload=payload)
    return data

  def get_researcher_profile(self, permalink, payload=None) -> Union[list, dict, None]:
    if payload is None:
      payload = {}
    data = self.request('GET', permalink, archivement_type='profile', payload=payload)
    return data

  def get_usage(self) -> None:
    return None


class AiohttpAdapter(Adapter):
  async def request(self, method: str, permalink: str, *,
                    archivement_type: str = "", query: str = "", payload: dict = {}, **kwargs) -> Optional[
    Union[list, dict]]:
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

  async def get_bulk(self, payload: dict = {}) -> str:
    data = await self.request('GET', '/_bulk', payload=payload)
    return data

  async def get_usage(self) -> None:
    return None


def main():
  with open('env/rmap_jwt_private.key', 'rb') as f_private:
    private_key = f_private.read()
  with open('env/rmap_client_id.key', 'r') as f_id:
    id = f_id.read()
  client_id = id
  client_secret = private_key
  scope = 'public_only'
  auth = Auth(client_id, client_secret, scope)
  access_token = auth.get_access_token()["access_token"]
  req = RequestsAdapter(access_token)
  payload = {"format": "json", "limit": 100, "institution_code": "0332000000"}
  print(req.search_researcher(payload))


async def aiomain():
  with open('env/rmap_jwt_private.key', 'rb') as f_private:
    private_key = f_private.read()


if __name__ == "__main__":
  main()
  # import asyncio
  # loop = asyncio.get_event_loop()
  # loop.run_until_complete(aiomain())

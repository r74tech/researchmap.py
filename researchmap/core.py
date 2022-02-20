from io import TextIOWrapper
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

# from .errors import (BadRequest, Forbidden, HTTPException, InternalServerError,
#                      NotFound, PayloadTooLarge, QuotaExceeded,
#                      ServiceUnavailable, TooManyRequests, URITooLong)

__all__ = ['Authentication', 'Auth', 'Adapter', 'RequestsAdapter', 'AiohttpAdapter']


class Authentication(metaclass=ABCMeta):
  """
  Researchmap authentication interface.
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  Args:
    :client_id: Client ID.
    :client_secret: Client secret.key.
    :iss: Issued at.
    :exp: Expiration.
    :sub: Subject.
  Returns:
    :access: Access token.
  """

  def __init__(self, client_id, client_secret, scope, *, iss: int = 30, exp: int = 30, sub=0):
    self.endpoint = 'https://api.researchmap.jp/oauth2/token'
    self.version = "2"
    self.grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    self.algorithm = "RS256"
    self.client_id = client_id
    self.client_secret = client_secret
    self.scope = scope
    self.iss = iss
    self.exp = exp
    self.sub = sub

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
    message = data.get('message', '') if data else ''
    if status_code == 302:
      raise Moved_Temporarily(response, message)
    elif status_code == 400:
      raise BadRequest(response, message)
    elif status_code == 403:
      raise Forbidden(response, message)
    elif status_code == 404:
      raise NotFound(response, message)
    elif status_code == 413:
      raise PayloadTooLarge(response, message)
    elif status_code == 414:
      raise URITooLong(response, message)
    elif status_code == 429:
      raise TooManyRequests(response, message)
    elif status_code == 456:
      raise QuotaExceeded(response, message)
    elif status_code == 503:
      raise ServiceUnavailable(response, message)
    elif 500 <= status_code < 600:
      raise InternalServerError(response, message)
    else:
      raise HTTPException(response, message)


class Auth(Authentication):
  def gen_jwt(self) -> str:
    payload = {
      "iss": self.client_id,
      "aud": self.endpoint,
      "sub": self.sub,
      "exp": datetime.datetime.now() + datetime.timedelta(seconds=self.exp),
      "iat": datetime.datetime.now() - datetime.timedelta(seconds=self.iss)
    }
    _jwt = jwt.encode(payload, self.client_secret,
                      algorithm=self.algorithm)
    return _jwt

  def gen_pubkey(self) -> str:
    privkey = serialization.load_pem_private_key(
      self.client_secret,
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
    if _jwt is None:
      _jwt = self.gen_jwt()
    if client_public is None:
      client_public = self.gen_pubkey()
    try:
      decoded_jwt = jwt.decode(_jwt, key=client_public,
                               audience=self.endpoint, algorithms=self.algorithm)
      if decoded_jwt['iss'] == self.client_id and decoded_jwt['sub'] == self.sub and decoded_jwt['aud'] == self.endpoint:
        return True
    except:
      return False

  def get_access_token(self, *, _jwt: str = None, **kwargs) -> Optional[Union[list, dict]]:
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
  def request(self, method: str,
              permalink: str, archivement_type: str, payload: dict = {}, **kwargs) -> Optional[Union[list, dict]]:
    raise NotImplementedError()

  @abstractmethod
  def get_usage(self) -> dict:
    raise NotImplementedError()

  def _check_status(self, status_code, response, data) -> Union[dict, list]:
    if 200 <= status_code < 300:
      return data
    message = data.get('message', '') if data else ''
    if status_code == 302:
      raise Moved_Temporarily(response, message)
    elif status_code == 400:
      raise BadRequest(response, message)
    elif status_code == 403:
      raise Forbidden(response, message)
    elif status_code == 404:
      raise NotFound(response, message)
    elif status_code == 413:
      raise PayloadTooLarge(response, message)
    elif status_code == 414:
      raise URITooLong(response, message)
    elif status_code == 429:
      raise TooManyRequests(response, message)
    elif status_code == 456:
      raise QuotaExceeded(response, message)
    elif status_code == 503:
      raise ServiceUnavailable(response, message)
    elif 500 <= status_code < 600:
      raise InternalServerError(response, message)
    else:
      raise HTTPException(response, message)


class RequestsAdapter(Adapter):
  def request(self, method: str, permalink: str, *,
              archivement_type: str = "", query: str = "", payload: dict = {}, **kwargs) -> Optional[Union[list, dict]]:

    headers = {
      'Authorization': 'Bearer {}'.format(self.authentication_key),
      'Accept': 'application/ld+json,application/json;q=0.1',
      'Content-Type': 'application/x-www-form-urlencoded'
    }
    url = self.base_url.format(permalink=permalink, archivement_type=archivement_type, query=query)
    print(payload)
    payload = urllib.parse.urlencode(payload)
    resp = requests.request(method, url, headers=headers, data=payload, **kwargs)

    print(resp.text)
    try:
      data = resp.json()
    except json.JSONDecodeError:
      data = resp.content
    return self._check_status(resp.status_code, resp, data)

  def get_bulk(self, payload) -> str:
    data = self.request('GET', '/_bulk', payload=payload)
    return data

  def search_researcher(self, payload) -> str:
    data = self.request('GET', '/researchers', payload=payload)
    return data

  def get_usage(self) -> None:
    return None


class AiohttpAdapter(Adapter):
  async def request(self, method: str, permalink: str, *,
                    archivement_type: str = "", query: str = "", payload: dict = {}, **kwargs) -> Optional[Union[list, dict]]:
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

  async def get_bulk(self, payload) -> str:
    data = await self.request('GET', '/_bulk', payload=payload)
    return data

  async def get_usage(self) -> None:
    return None


def main():
  with open('env/rmap_jwt_private.key', 'rb') as f_private:
    private_key = f_private.read()
  with open('env/rmap_client_id.key', 'rb') as f_id:
    client_id = f_id.read()
  client_secret = private_key
  scope = 'read'
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

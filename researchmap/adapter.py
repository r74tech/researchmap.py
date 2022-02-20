from io import TextIOWrapper
import json
from abc import ABCMeta, abstractmethod
from typing import List, Optional, Union
import jwt
import aiohttp

import requests

from .errors import (BadRequest, Forbidden, HTTPException, InternalServerError,
                     NotFound, PayloadTooLarge, QuotaExceeded,
                     ServiceUnavailable, TooManyRequests, URITooLong)

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

  def __init__(self, client_id, client_secret, iss, exp, sub):
    self.endpoint = 'https://api.researchmap.com/v2/oauth/token'
    self.client_id = client_id
    self.client_secret = client_secret
    self.iss = iss
    self.exp = exp
    self.sub = sub

  @abstractmethod
  def get_access_token(self, client_id, client_secret, iss, exp, sub):
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


class Adapter(metaclass=ABCMeta):
  def __init__(self, authentication_key: str) -> None:
    self.base_url = 'https://api.researchmap.jp/{permalink}/{archivement_type}?{query}'
    self.authentication_key = authentication_key

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

class Auth(Authentication):
  def request(self, method: str, path: str, data: dict = {}, headers: dict = {}, **kwargs) -> Optional[Union[list, dict]]:
    path = self.endpoint + path
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    params = {
      'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      'assertion': encoded_jwt,
      'scope': 'read',
      'version': "2"
    }



class RequestsAdapter(Adapter):
  def request(self, method: str, permalink: str, *,
              archivement_type: str = "", payload: dict = {}, **kwargs) -> Optional[Union[list, dict]]:
    payload['auth_key'] = self.auth_key
    url = self.base_url.format(permalink=permalink, archivement_type=archivement_type)

    resp = requests.request(method, url, data=payload, **kwargs)
    try:
      data = resp.json()
    except json.JSONDecodeError:
      data = resp.content
    return self._check_status(resp.status_code, resp, data)

  def get_bulk(self, payload) -> str:
    data = self.request('POST', '/_bulk', payload=payload)
    return data

  def get_usage(self) -> None:
    return None


class AiohttpAdapter(Adapter):

  async def request(self, method: str,
                    path: str, payload: dict = {}, **kwargs) -> Optional[Union[list, dict]]:
    payload['auth_key'] = self.auth_key
    url = self.base_url.format(permalink=permalink, archivement_type=archivement_type)

    async with aiohttp.request(
      method, url, data=payload, **kwargs) as resp:
      try:
        data = await resp.json(content_type=None)
      except json.JSONDecodeError:
        data = await resp.read()
      status_code = resp.status
    return self._check_status(status_code, resp, data)

  def get_bulk(self, payload) -> str:
    data = self.request('POST', '/_bulk', payload=payload)
    return data

  def get_usage(self) -> None:
    return

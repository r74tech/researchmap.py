from typing import List
import urllib.parse

from .adapter import Adapter

__all__ = ['Wrapper']


class Wrapper:
  """Wrapper class for the Adapter class.

  This class is used to wrap the Adapter class and provide a more
  convenient interface for the user.
  """

  def __init__(self, adapter: Adapter) -> None:
    self._adapter = adapter

  def get_bulk(self, params=None) -> dict:
    """Get a list of researchers from the API.

    Parameters
    ----------
    params : :class:`dict`
      A dictionary containing the parameters to be passed to the API.
      The payload to send to the API. Defaults to None.

    Returns
    -------
    :class:`dict`
    """
    return self._adapter.get_bulk(params=params)

  def set_bulk(self, jsondata=None, params=None) -> dict:
    """Get a list of researchers from the API.

    Parameters
    ----------
    jsondata : :class:`dict`
      A dictionary containing the parameters to be passed to the API.
      The payload to send to the API. Defaults to None.
    params : :class:`dict`
      A dictionary containing the parameters to be passed to the API.

    Returns
    -------
    :class:`dict`
    """
    if params is None:
      params = {}
    if jsondata is None:
      jsondata = {}
    data = self._adapter.set_bulk(params=params, jsondata=jsondata)
    print(data)
    bulk_data = {}
    bulk_data['id'] = urllib.parse.parse_qs(urllib.parse.urlparse(data['url']).query)['id'][0]
    error = self._adapter.get_bulk_results(bulk_data)
    bulk_data['display_type'] = "success"
    print(bulk_data)
    succeed = self._adapter.get_bulk_results(bulk_data)
    print(succeed)
    print(error)
    return self._adapter.get_bulk_results(bulk_data)

  def set_bulk_apply(self, params=None) -> dict:
    """Get a list of researchers from the API.

    Parameters
    ----------
    params : :class:`dict`
      A dictionary containing the parameters to be passed to the API.

    Returns
    -------
    :class:`dict`
    """
    if params is None:
      params = {}
    return self._adapter.set_bulk_apply(params=params)

  def get_bulk_results(self, params=None) -> dict:
    """Get a list of researchers from the API.

    Parameters
    ----------
    params : :class:`dict`
      A dictionary containing the parameters to be passed to the API.


    Returns
    -------
    :class:`dict`
    """
    if params is None:
      params = {}
    return self._adapter.get_bulk_results(params=params)

  def search_researcher(self, payload=None) -> dict:
    """Search for a researcher in the API.

    Parameters
    ----------
    payload : :class:`dict`
      A dictionary containing the parameters to be passed to the API.
      The payload to send to the API. Defaults to None.

    Returns
    -------
    :class:`dict`
    """
    if payload is None:
      payload = {}
    return self._adapter.search_researcher(payload)

  def usage(self) -> dict:
    return self._adapter.get_usage()

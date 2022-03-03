from typing import List


from .adapter import Adapter

__all__ = ['Wrapper']


class Wrapper:
  """Wrapper class for the Adapter class.

  This class is used to wrap the Adapter class and provide a more
  convenient interface for the user.
  """
  def __init__(self, adapter: Adapter) -> None:
    self._adapter = adapter

  def get_bulk(self, payload=None) -> dict:
    """Get a list of researchers from the API.

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
    return self._adapter.get_bulk(payload)

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

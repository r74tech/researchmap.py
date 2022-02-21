from typing import List

from .adapter import Adapter

__all__ = ['Wrapper']


class Wrapper:
  def __init__(self, adapter: Adapter) -> None:
    self._adapter = adapter

  def get_bulk(self,payload: dict={}) -> dict:
    return self._adapter.get_bulk(payload)

  def search_researcher(self, payload: dict={}):
    return self._adapter.search_researcher(payload)

  def usage(self) -> dict:
    return self._adapter.get_usage()
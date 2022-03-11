from enum import Enum

__all__ = [
  'SourceLang',
  'TargetLang',
  'SplitSentences',
  'PreserveFormatting',
  'Formality'
]


class GetFormatted(Enum):
  json = 'json'
  csv = 'csv'
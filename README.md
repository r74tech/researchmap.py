# researchmap.py
[![GitHub license](https://img.shields.io/github/license/RTa-technology/researchmap.py)](https://github.com/RTa-technology/researchmap.py/blob/main/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/RTa-technology/researchmap.py)](https://github.com/RTa-technology/researchmap.py/issues)
[![GitHub forks](https://img.shields.io/github/forks/RTa-technology/researchmap.py)](https://github.com/RTa-technology/researchmap.py/network)
[![GitHub stars](https://img.shields.io/github/stars/RTa-technology/researchmap.py)](https://github.com/RTa-technology/researchmap.py/stargazers)
[![PyPI version](https://badge.fury.io/py/researchmap.py.svg)](https://badge.fury.io/py/researchmap.py)
[![Python Versions](https://img.shields.io/pypi/pyversions/researchmap.py.svg)](https://pypi.org/project/researchmap.py/)
[![Downloads](https://pepy.tech/badge/researchmap-py)](https://pepy.tech/project/researchmap-py)

## Key Features
* Modern Pythonic API using `async` and `await`.
* Optimised in both speed and memory.

## Installing
Python 3.8 or higher is required

To install the library without full voice support, you can just run the following command:
```bash
# Linux/macOS
python3 -m pip install -U researchmap.py

# Windows
py -3 -m pip install -U researchmap.py
```

To install the development version, do the following:
```
$ git clone https://github.com/RTa-technology/researchmap.py
$ cd researchmap.py
$ python3 -m pip install -U .
```
## Quick Example
```py
import researchmap

def main():
  with open('env/rmap_jwt_private.key', 'rb') as f_private:
    private_key = f_private.read()
  with open('env/rmap_client_id.key', 'r') as f_id:
    id = f_id.read()
  client_id = id
  client_secret = private_key
  scope = 'read researchers'
  auth = researchmap.Auth(client_id, client_secret, scope)
  access_token = auth.get_access_token()["access_token"]
  req = researchmap.RequestsAdapter(access_token)
  payload = {"format": "json", "limit": 100, "institution_code": "所属機関の機関コード"}
  print(req.get_bulk(payload))

if __name__ == "__main__":
  main()
```

## Contributing
### How to localize
```bash
$ docs/make.bat gettext
$ sphinx-intl update -p docs/_build/gettext -l ja
$ # Translate the po file.
$ Set-Item env:SPHINXOPTS "-D language=ja"
$ docs/make.bat html
```

## Links
* [Documentation](https://researchmappy.readthedocs.io/)
* [API Documents](https://researchmap.jp/public/other-document/specification)

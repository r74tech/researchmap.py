# researchmap.py


## Contributing
### How to localize
```bash
$ docs/make.bat gettext
$ sphinx-intl update -p docs/_build/gettext -l ja
$ # Translate the po file.
$ Set-Item env:SPHINXOPTS "-D language=ja"
$ docs/make.bat html
```

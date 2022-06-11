import re
from codecs import open
from os import path
import setuptools

version = ''
with open('researchmap/__init__.py') as f:
    version = re.search(
        r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', f.read(), re.MULTILINE).group(1)

root_dir = path.abspath(path.dirname(__file__))

with open('README.md', 'r', encoding="utf-8") as f:
    long_description = f.read()

setuptools.setup(
    name='researchmap.py',
    version=version,
    license='MIT',
    description='This is a wrapper for the Researchmap API.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/RTa-technology/researchmap.py',
    author='RTa-technology',
    packages=["researchmap"],
    install_requires=[
        "PyJWT",
        "aiohttp",
        "requests"
        "cryptography",
        "sphinx",
        "sphinxcontrib-trio",
        "sphinxcontrib-websupport",
        "myst-parser",
        "urllib3",
    ],
    classifiers=[
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)

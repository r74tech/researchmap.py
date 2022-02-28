from setuptools import setup, find_packages

setup(
  name='researchmap',
  version='0.1.0',
  license='MIT',
  description='This is a wrapper for the Researchmap API.',
  author='RTa-technology',
  packages=find_packages(where='researchmap'),
  package_dir={'': 'researchmap'},
)
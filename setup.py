#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='cryptos',
      version='0.0.9',
      description='Python Crypto Tools',
      author='Paul Martin',
      author_email='paulmartinforwork@gmail.com',
      url='http://github.com/primal100/pybitcointools',
      packages=['cryptos'],
      scripts=['cryptotool'],
      include_package_data=True,
      data_files=[("", ["LICENSE"]), ("cryptos", ["cryptos/english.txt"])],
      )

#!/usr/bin/env python

from distutils.core import setup

setup(name='bitcoin',
      version='1.1.13',
      description='Python Bitcoin Tools',
      author='Vitalik Buterin',
      author_email='vbuterin@gmail.com',
      url='http://github.com/vbuterin/pybitcointools',
      packages=['bitcoin'],
      scripts=['pybtctool']
      )

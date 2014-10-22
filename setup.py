#!/usr/bin/env python

from setuptools import setup

setup(name='bitcoin',
      version='1.1.17',
      description='Python Bitcoin Tools',
      author='Vitalik Buterin',
      author_email='vbuterin@gmail.com',
      url='http://github.com/vbuterin/pybitcointools',
      install_requires='six==1.8.0',
      packages=['bitcoin'],
      scripts=['pybtctool'],
      data_files=[("", ["LICENSE"])]
      )

#!/usr/bin/env python
from setuptools import setup, find_packages

setup(name='cryptos',
      version='1.36',
      description='Python Crypto Coin Tools',
      long_description=open('README.md').read(),
      author='Paul Martin',
      author_email='paulmartinforwork@gmail.com',
      url='http://github.com/primal100/pybitcointools',
      packages=find_packages(),
      scripts=['cryptotool'],
      include_package_data=True,
      classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Intended Audience :: Developers',
            'Intended Audience :: Education',
            'License :: OSI Approved :: MIT License',
            'Operating System :: OS Independent',
            'Programming Language :: Python',
            'Programming Language :: Python :: 2',
            'Programming Language :: Python :: 3',
            'Topic :: Security :: Cryptography',
      ],
      )

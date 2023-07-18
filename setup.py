#!/usr/bin/env python
from setuptools import setup, find_packages

setup(name='cryptos',
      version='2.0.9',
      description='Python Crypto Coin Tools',
      long_description=open('README.md').read(),
      long_description_content_type='text/markdown',
      author='Paul Martin',
      author_email='greatestloginnameever@gmail.com',
      url='http://github.com/primal100/pybitcointools',
      packages=find_packages(),
      include_package_data=True,
      install_requires=[
            "requests",
            "pbkdf2",
            "pycryptodomex",
            "aiorpcx",
            "certifi",
            "janus",
            "packaging",
            "typing_extensions"
      ],
      classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Intended Audience :: Developers',
            'Intended Audience :: Education',
            'License :: OSI Approved :: MIT License',
            'Operating System :: OS Independent',
            'Programming Language :: Python',
            'Programming Language :: Python :: 3',
            'Topic :: Security :: Cryptography',
      ],
      entry_points='''
            [console_scripts]
            broadcast=crypto_scripts.broadcast:main
            convert_private_key=crypto_scripts.convert_private_key:main
            create_private_key=crypto_scripts.create_private_key:main
            cryptosend=crypto_scripts.cryptosend:main
            explorer=crypto_scripts.explorer:main
            get_block_sizes=crypto_scripts.get_block_sizes:main
            subscribe=crypto_scripts.subscribe:main
            view_private_key_addresses=crypto_scripts.view_private_key_addresses:main
            '''
      )

#!/usr/bin/env python

from setuptools import setup

try:
    requires = open('requirements.txt', 'r').read().splitlines()
except Exception:
    requires = []

version = open('VERSION', 'r').read().strip()

setup(name='hashnist',
      version=version,
      author='Alfredo',
      author_email='aandreswork@hotmail.com',
      packages=['hashnist'],
      install_requires=requires
      )

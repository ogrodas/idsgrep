#!/usr/bin/env python
# -*- coding: utf-8 -*-
from distutils.core import setup

setup(
    name='IDSGrep',
    version='1.0',
    author='Ole Morten Grodås',
    author_email='grodaas+idsgrep@gmail.com',
    packages=['idsgrep', 'idsgrep.test'],
    scripts=['bin/idsgrep'],
    url='',
    license='LICENSE.txt',
    description='Grep that understands IP,CDIR,IP-ranges and domains',
    long_description=open('README.txt').read(),
    install_requires=[
        "pymongo >= 2.2",
        "ahocorasick"
    ],
)
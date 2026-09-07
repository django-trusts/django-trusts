#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os
from setuptools import setup, find_packages


README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()
REQUIREMENTS = open(os.path.join(os.path.dirname(__file__), 'requirements.txt')).read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-trusts',
    version='1.0.0.dev0',
    description='Django authorization add-on for multiple organizations and object-level permission settings',
    author='Thomas Yip',
    author_email='thomasleaf@gmail.com',
    long_description=README,
    url='http://github.com/beedesk/django-trusts',
    packages=find_packages(exclude=[]),
    test_suite="tests.runtests.runtests",
    include_package_data=True,
    zip_safe=False,
    install_requires=REQUIREMENTS,
    license='BSD 2-Clause',
    classifiers=[
	'Development Status :: 4 - Beta',
	'Framework :: Django :: 1.8',
	'Intended Audience :: Developers',
	'Intended Audience :: Information Technology',
	'Intended Audience :: System Administrators',
	'License :: OSI Approved :: BSD License',
	'Natural Language :: English',
	'Operating System :: OS Independent',
	'Programming Language :: Python',
	'Programming Language :: Python :: 2',
	'Topic :: Software Development :: Libraries',
    ],
)

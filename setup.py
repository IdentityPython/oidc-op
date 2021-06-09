#!/usr/bin/env python3
#
# Copyright (C) 2019 Roland Hedberg, Sweden
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import re
import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand

__author__ = 'Roland Hedberg'


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest

        errno = pytest.main(self.test_args)
        sys.exit(errno)


extra_install_requires = []

# read the contents of the README file
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

with open('src/oidcop/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    name="oidcop",
    version=version,
    description="Python implementation of OIDC Provider",
    author="Roland Hedberg",
    author_email="roland@catalogix.se",
    license="Apache 2.0",
    url='https://github.com/IdentityPython/oidcop',
    package_dir={"": "src"},
    packages=["oidcop", 'oidcop/oidc', 'oidcop/authz',
              'oidcop/user_authn', 'oidcop/user_info',
              'oidcop/oauth2', 'oidcop/oidc/add_on', 'oidcop/oauth2/add_on',
              'oidcop/session', 'oidcop/token'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires=[
        "oidcmsg==1.3.2",
        "cryptojwt==1.5.2",
        "pyyaml",
        "jinja2>=2.11.3",
        "responses>=0.13.0"
    ],
    zip_safe=False,
    cmdclass={'test': PyTest},
    long_description=long_description,
    long_description_content_type='text/markdown',
)

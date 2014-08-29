#!/usr/bin/env python
from distutils.core import setup
from pops import __version__ as version

setup(
    name='pypops',
    version=version,
    packages=[''],
    url='https://github.com/shuge/pops',
    license='MIT License',
    author='Shuge Lee',
    author_email='shuge.lee@gmail.com',
    description='POPS is a HTTP proxy server and HTTP proxy slot server.',

    platforms = ["Mac OS X", "Linux"],

    scripts = [
        "pops.py",
    ],

    install_requires = [
        "argparse",
        "python-daemon",
        ],
)

#!/usr/bin/env python
from distutils.core import setup

setup(
    name='pops',
    version='201401',
    packages=[''],
    url='https://github.com/shuge/pops',
    license='MIT License',
    author='Shuge Lee',
    author_email='shuge.lee@gmail.com',
    description='POPS is a simple HTTP proxy server and HTTP proxy slot server.',

    platforms = ["Mac OS X", "Linux"],

    scripts = [
        "pops.py",
    ],

    install_requires = [
        "requests",
        "argparse",
        "lockfile",
        "python-daemon",
        ],
)

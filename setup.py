# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name="downbreaker-runner.py",
    version="1.0",
    author="Lorenz Heiler",
    author_email="contact@lorenzheiler.com",
    url="www.lorenzheiler.com",

    description="Recursive Traversal x86 Disassembler for PE files. ",
    long_description="",
    classifiers="",

    entry_points={
        "console_scripts": ['downbreaker = downbreaker.downbreaker:main']
        },
    packages=['downbreaker'],

    install_requires=[
        'pefile',
        'capstone',
    ],

)
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name="crumble",
    version="0.1",
    author="Lorenz Heiler",
    author_email="contact@lorenzheiler.com",
    url="www.lorenzheiler.com",

    description="Recursive Disassembler for PE files (x86) ",
    long_description="",
    classifiers="",

    entry_points={
        "console_scripts": ['crumble = crumble.crumble:main']
        },
    packages=['crumble'],

    install_requires=[
        'pefile',
        'capstone',
    ],

)
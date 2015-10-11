Crumble - A Recursive Disassembler (x86)
========================================
This is a crossplatform commandline tool, written in Python, which disassembles 32bit PE files with recursive traversal and saves the results as a .json file.

Incomplete features:
--------------------
* The results are far away from perfect (no indirect control flows)
* Detecting functionnames from symboltables if given
* Detecting strings
* Detecting functionarguments

Installation
------------
You can install this tool with ``$ pip install .``.

Usage
-----
After installation you can run ``$ crumble -h`` for information about the arguments.

Additional Libraries used from PyPI
-----------------------------------
* `Capstone <http://www.capstone-engine.org/>`_
* `pefile  <https://pypi.python.org/pypi/pefile>`_
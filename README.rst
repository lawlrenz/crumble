Recursive Disassembler (x86)
============================
This is a crossplatform commandline tool, written in Python, which can disassemble 32bit PE files and save the results as a .json file.

The results are not yet perfect, as well as the output ist not working so far.

Installation
------------
You can install this tool with ``$ python setup.py install``.

Usage
-----
After installation you can run ``$ downbreaker yourpefile.exe numberofthreads``.

Additional Libaries used (pypi)
-------------------------------
* pefile
* capstone
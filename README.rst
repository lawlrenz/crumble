Recursive Disassembler (x86)
============================
This is a crossplatform commandline tool, written in Python, which can disassemble 32bit PE files and save the results as a .json file.

The results are far away from perfect, as well as the output ist not working so far.

Installation
------------
You can install this tool with ``$ pip install .``.

Usage
-----
After installation you can run ``$ downbreaker yourpefile.exe numberofthreads``. I recommend 1 thread at the moment.

Additional Libaries used (pypi)
-------------------------------
* pefile
* capstone
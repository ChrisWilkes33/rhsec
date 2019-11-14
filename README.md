# rhsec

Reaches out to RedHat Security Data API and returns a .csv file containing the last 30 days worth of CVRF files.

Requires two arguments, the first is a complete path to an output file (ex: c:/file.csv), the second is which version of enterprise linux to return CVRF information for (7 and 8 have been tested)

to call the script: > ./rhsec.py /path/to/file.csv 7

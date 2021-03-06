@echo off
title UTscapy - All tests - PY2
set MYDIR=%~dp0..
set PWD=%MYDIR%
set PYTHONPATH=%MYDIR%
set PYTHONDONTWRITEBYTECODE=True
if [%1]==[] (
  python "%MYDIR%\scapy\tools\UTscapy.py" -c configs\\windows2.utsc -o scapy_regression_test_%date:~6,4%_%date:~3,2%_%date:~0,2%.html
) else (
  python "%MYDIR%\scapy\tools\UTscapy.py" %*
)
PAUSE
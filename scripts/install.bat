@echo off

cd %~dp0..

call pip install -e ".[dev]"
call poe hook

pause
exit /B 0

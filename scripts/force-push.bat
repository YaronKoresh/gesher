@echo off

cd %~dp0..

@echo off
setlocal EnableDelayedExpansion

set "MSG_FILE=%TEMP%\git_msg_%RANDOM%.txt"

echo Enter message (Type EOF on a new line to finish):
:InputLoop
set "Line="
set /p "Line="
if "!Line!"=="EOF" goto DoCommit
if not defined Line (
    echo. >> "%MSG_FILE%"
) else (
    echo !Line! >> "%MSG_FILE%"
)
goto InputLoop

:DoCommit
call git add .
call git commit -F "%MSG_FILE%" --no-verify
call git push --no-verify

if exist "%MSG_FILE%" del "%MSG_FILE%"

pause
exit /B 0

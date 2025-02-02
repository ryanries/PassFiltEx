@echo off
clang PassFiltExTest.c -o PassFiltExTest.exe -Wall -Wextra -O0 -g -D_DEBUG -D_WIN64
if %ERRORLEVEL% neq 0 goto :failed
copy .\PassFiltExTest.exe ..\bin\debug\
echo Debug build succeeded.
exit
:failed
echo Build failed!



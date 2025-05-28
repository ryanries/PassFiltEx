@echo off
REM ====================================
REM  Build script for PassFiltEx  
REM  Joseph Ryan Ries 2025         
REM ====================================
set "PROJECTNAME=PassFiltEx"
set "RCEXE="C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\rc.exe""
set "INCPATH1="C:\Program Files (x86)\Windows Kits\10\Include\10.0.20348.0\um""
set "INCPATH2="C:\Program Files (x86)\Windows Kits\10\Include\10.0.20348.0\shared""

%RCEXE% /nologo /r /i %INCPATH1% /i %INCPATH2%  %PROJECTNAME%.rc
if "%~1"=="" goto no_args
if "%~1"=="debug" goto debug_build
if "%~1"=="release" goto release_build
:no_args
echo Must specify either debug or release!
exit
:debug_build 
if not exist .\bin\ mkdir .\bin
if not exist .\bin\debug\ mkdir .\bin\debug
clang -shared -o .\bin\debug\%PROJECTNAME%.dll *.c -Wall -Wextra -Wformat -march=x86-64-v3 -O0 -g3 -D_DEBUG -D_WIN64 -Wl,%PROJECTNAME%.res
if %ERRORLEVEL% neq 0 goto build_fail
echo Debug build succeeded.
exit
:release_build
if not exist .\bin\ mkdir .\bin
if not exist .\bin\release\ mkdir .\bin\release
clang -shared -o .\bin\release\%PROJECTNAME%.dll *.c -Wall -Wextra -Wformat -march=x86-64-v3 -O3 -D_WIN64 -Wl,%PROJECTNAME%.res
if %ERRORLEVEL% neq 0 goto build_fail
echo Release build succeeded.
exit
:build_fail
echo **** BUILD FAILURE ****
exit %ERRORLEVEL%

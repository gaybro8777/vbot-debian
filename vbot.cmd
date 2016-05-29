@echo off
cd .\vbot.debian\bin\Debug
vbot.debian.exe %*
REM IF "%1"=="ui" (
REM	DesktopCanary.UI.exe %* 
REM	goto end
REM )
REM IF "%1"=="run" (
REM	start DesktopCanary.Service.exe %* 
REM ) ELSE (
REM	DesktopCanary.Service.exe %*
REM )
:end
cd ..\..\..
@echo off
rem Double-click to install NetLeash (asks for Administrator rights).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*

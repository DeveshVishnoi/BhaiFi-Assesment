@echo off
net stop InfinityAgent
sc.exe delete InfinityAgent
del /f /q "C:\Program Files (x86)\BhaiFi Agent\agent.exe"

reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\BhaiFi\BhaiFi_Agent" /f


rmdir /s /q "C:\Program Files (x86)\BhaiFi Agent\.logs"


exit /b 0
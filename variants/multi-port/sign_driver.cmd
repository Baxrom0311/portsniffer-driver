@echo off
cd /d C:\PortSnifferTest\portsniffer-driver\variants\multi-port\redist_AMD64
C:\WinDDK\7600.16385.1\bin\amd64\signtool.exe sign /v /a /s PrivateCertStore /n PortSnifferTest2 EnlyzePortSniffer2.sys

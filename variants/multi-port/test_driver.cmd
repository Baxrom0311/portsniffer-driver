@echo off
cd /d C:\PortSnifferTest\portsniffer-driver\variants\multi-port\redist_AMD64

echo Attaching to COM10...
PortSniffer-Tool2.exe /attach COM10

echo Starting Python script in background...
start /B python test_com10.py

echo Starting PortSniffer monitor in background...
start /B "" "PortSniffer-Tool2.exe" /monitor COM10 RWC > sniff.log

echo Waiting for 10 seconds to capture traffic...
timeout /t 10 > nul

echo Terminating monitor...
taskkill /IM PortSniffer-Tool2.exe /F

echo Detaching from COM10...
PortSniffer-Tool2.exe /detach COM10

echo Displaying results:
type sniff.log

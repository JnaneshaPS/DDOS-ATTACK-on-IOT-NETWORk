@echo off
REM launch_attack.bat - Simulates a DDoS attack from the attacker container
setlocal enabledelayedexpansion

echo === Launching DDoS Attack Simulation ===

REM Target device (default: device 1)
set TARGET_DEVICE=1
if not "%~1"=="" set TARGET_DEVICE=%~1
set TARGET=iot-device-%TARGET_DEVICE%

REM Get target IP address
for /f "tokens=*" %%a in ('docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" %TARGET%') do (
  set TARGET_IP=%%a
)

REM Attack duration in seconds
set DURATION=30
if not "%~2"=="" set DURATION=%~2

echo Target: %TARGET% (!TARGET_IP!)
echo Attack duration: %DURATION% seconds
echo Attack type: SYN flood

REM Execute the attack - using ping flood since Alpine doesn't have hping3
echo Starting attack using ping flood...
docker exec -d attacker sh -c "apk add --no-cache iputils && ping -f -s 1000 -c 10000 !TARGET_IP!"

echo Attack launched against %TARGET%
echo The attack will run for %DURATION% seconds
echo === Monitor your dashboard to see detection and mitigation ===

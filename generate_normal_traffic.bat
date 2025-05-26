@echo off
REM generate_normal_traffic.bat - Simulates normal IoT device traffic
setlocal enabledelayedexpansion

echo === Generating Normal IoT Traffic Patterns ===

REM Number of ping iterations
set ITERATIONS=10
if not "%~1"=="" set ITERATIONS=%~1
echo Running %ITERATIONS% iterations of normal traffic...

REM Generate ping traffic between devices
for /l %%j in (1, 1, %ITERATIONS%) do (
  echo Traffic iteration %%j of %ITERATIONS%
  
  REM Each device pings another device
  for /l %%i in (1, 1, 5) do (
    REM Calculate target device (round-robin style)
    set /a TARGET=%%i %% 5 + 1
    
    echo iot-device-%%i pinging iot-device-!TARGET!
    docker exec iot-device-%%i ping -c 3 iot-device-!TARGET!
  )
  
  REM Small delay between iterations
  timeout /t 2 /nobreak > nul
)

echo === Normal IoT Traffic Generation Complete ===

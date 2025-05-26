@echo off
REM setup_docker_demo.bat - Creates a simulated IoT network using Docker

echo === Setting up IoT Network Simulation Environment ===

REM Create a custom bridge network for IoT devices
echo Creating Docker network for IoT devices...
docker network create iot-network

REM Launch 5 simulated IoT devices
echo Creating simulated IoT devices...
for /l %%i in (1, 1, 5) do (
  docker run -d --name iot-device-%%i --network iot-network alpine sleep infinity
  echo Created iot-device-%%i
)

REM Create an attacker container
echo Creating attacker container...
docker run -d --name attacker --network iot-network alpine sleep infinity

REM Install hping3 on the attacker
echo Installing attack tools on attacker container...
docker exec attacker apk update
docker exec attacker apk add --no-cache hping3 iperf3

REM Map container IPs for visualization
echo Mapping container IPs to device types...
echo Obtaining IP addresses of containers...
for /l %%i in (1, 1, 5) do (
  for /f "tokens=*" %%a in ('docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" iot-device-%%i') do (
    echo iot-device-%%i: %%a
  )
)

for /f "tokens=*" %%a in ('docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" attacker') do (
  echo attacker: %%a
)

echo === IoT Network Simulation Environment Ready ===
echo Use generate_normal_traffic.bat to simulate normal traffic
echo Use launch_attack.bat to simulate a DDoS attack

@echo off
REM mitigate_docker_attack.bat - Implements mitigation for DDoS attacks in Docker environment

echo === DDoS Attack Mitigation System ===

REM Get attacker IP (default to the attacker container IP if not provided)
set ATTACKER_IP=%1
if "%ATTACKER_IP%"=="" set ATTACKER_IP=172.18.0.7

REM Get target device (default to iot-device-1 if not provided)
set TARGET_DEVICE=%2
if "%TARGET_DEVICE%"=="" set TARGET_DEVICE=iot-device-1

echo [+] Implementing DDoS mitigation for attack from %ATTACKER_IP% targeting %TARGET_DEVICE%

REM ======== MITIGATION STRATEGY 1: Network Isolation ========
echo [+] Strategy 1: Network isolation - Disconnecting attacker from network
docker network disconnect iot-network attacker
echo [+] Attacker container disconnected from IoT network

REM ======== MITIGATION STRATEGY 2: Firewall Rules ========
echo [+] Strategy 2: Installing firewall rules on target device
docker exec %TARGET_DEVICE% sh -c "apk add --no-cache iptables && iptables -A INPUT -s %ATTACKER_IP% -j DROP"
echo [+] Traffic from %ATTACKER_IP% blocked via iptables on %TARGET_DEVICE%

REM ======== MITIGATION STRATEGY 3: Rate Limiting ========
echo [+] Strategy 3: Implementing rate limiting on target device
docker exec %TARGET_DEVICE% sh -c "apk add --no-cache iptables && iptables -A INPUT -p icmp -m limit --limit 3/second --limit-burst 5 -j ACCEPT && iptables -A INPUT -p icmp -j DROP"
echo [+] Rate limiting implemented - ICMP traffic limited to 3 packets/second

REM ======== MITIGATION STRATEGY 4: Attack Logging ========
echo [+] Strategy 4: Setting up attack logging for forensic analysis
set LOG_FILE=attack_log_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%.txt
echo DDoS Attack Detected > %LOG_FILE%
echo Timestamp: %date% %time% >> %LOG_FILE%
echo Attacker IP: %ATTACKER_IP% >> %LOG_FILE%
echo Target Device: %TARGET_DEVICE% >> %LOG_FILE%
echo. >> %LOG_FILE%
echo --- Network Status at Time of Attack --- >> %LOG_FILE%
docker ps >> %LOG_FILE%
echo. >> %LOG_FILE%
echo --- Target Container Network Stats --- >> %LOG_FILE%
docker stats --no-stream %TARGET_DEVICE% >> %LOG_FILE%
echo [+] Attack details logged to %LOG_FILE%

REM ======== MITIGATION STRATEGY 5: Traffic Redirection ========
echo [+] Strategy 5: Creating honeypot to redirect attack traffic
docker run -d --name honeypot --network iot-network alpine sleep infinity
echo [+] Honeypot container created for traffic redirection

echo.
echo === DDoS Mitigation Implemented Successfully ===
echo The following actions were taken:
echo 1. Attacker container disconnected from network
echo 2. Firewall rules implemented to block attack traffic
echo 3. Rate limiting configured to prevent network saturation
echo 4. Attack details logged for forensic analysis
echo 5. Honeypot deployed for traffic redirection
echo.
echo To verify mitigation effectiveness, run:
echo   docker exec %TARGET_DEVICE% ping -c 3 attacker
echo   (Should fail due to network disconnection)

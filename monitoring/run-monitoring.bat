@echo off
setlocal
cd /d "%~dp0.."
call mvn -q package
if errorlevel 1 exit /b 1
cd monitoring
call mvn -q package dependency:copy-dependencies -DoutputDirectory=target/dependency
if errorlevel 1 exit /b 1
if "%~1"=="" (
  echo Usage: monitoring\run-monitoring.bat ^<input.pcap^> ^<output.pcap^> [Main options]
  exit /b 1
)
java -cp "..\target\classes;target\classes;target\dependency\*" monitoring.MonitoringMain %*

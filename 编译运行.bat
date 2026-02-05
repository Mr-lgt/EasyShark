@echo off

rem 批处理文件：启动PowerShell编译运行脚本
rem 双击此文件即可自动编译并运行EasyTshark项目

set "SCRIPT_PATH=%~dp0build_and_run.ps1"

rem 使用PowerShell执行脚本
powershell.exe -ExecutionPolicy Bypass -File "%SCRIPT_PATH%"

pause

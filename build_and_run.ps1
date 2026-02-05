# PowerShell脚本：编译并运行EasyTshark项目
# 此脚本适用于Windows 10环境，使用PowerShell命令行

<#
.SYNOPSIS
编译并运行EasyTshark项目

.DESCRIPTION
该脚本会自动完成以下操作：
1. 进入build目录
2. 运行CMake配置
3. 编译项目
4. 启动EasyTshark程序

.EXAMPLE
运行脚本：
.uild_and_run.ps1

使用说明：
1. 运行脚本后，会提示输入PCAP文件路径
2. 分析完成后，会提示输入要查看的数据包编号
3. 数据包详情会保存为JSON文件到项目根目录

注意事项：
- 确保已安装CMake和编译器（如MinGW或Visual Studio）
- 确保build目录已存在
#>

# 设置工作目录
Set-Location -Path "$PSScriptRoot\build"

# 运行CMake配置
Write-Host "正在运行CMake配置..." -ForegroundColor Cyan
cmake ..
if ($LASTEXITCODE -ne 0) {
    Write-Host "CMake配置失败！" -ForegroundColor Red
    exit 1
}

# 编译项目
Write-Host "\n正在编译项目..." -ForegroundColor Cyan
cmake --build .
if ($LASTEXITCODE -ne 0) {
    Write-Host "编译失败！" -ForegroundColor Red
    exit 1
}

# 运行程序
Write-Host "\n编译成功！正在启动EasyTshark..." -ForegroundColor Green
Write-Host "=" * 50
Write-Host "使用提示："
Write-Host "1. 输入PCAP文件的完整路径（如：E:\pcap\capture.pcap）"
Write-Host "2. 分析完成后，输入要查看的数据包编号"
Write-Host "3. 结果将保存为JSON文件（如：17.json）"
Write-Host "=" * 50

.\EasyTshark.exe

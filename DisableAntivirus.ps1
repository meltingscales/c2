# Disable Windows Defender Real-Time Protection
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable Windows Defender Scheduled Scans
Set-MpPreference -DisableIOAVProtection $true

# Disable Windows Defender Cloud-Based Protection
Set-MpPreference -MAEnableCloudProtection $false

# Stop the Windows Defender Service
Stop-Service -Name "WinDefend" -Force

# Set the Windows Defender Service to be Disabled
Set-Service -Name "WinDefend" -StartupType Disabled

Write-Host "Windows Defender has been disabled."

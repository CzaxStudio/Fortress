# Fortress .frt File Type Installer
# Right-click -> Run with PowerShell (as Administrator)
# Registers: custom icon + Fortress Script type label + double-click to run

$ExePath = "C:\\Users\\DELL\\Downloads\\Fortress\\fortress.exe"
$IcoPath = "C:\\Users\\DELL\\Downloads\\Fortress\\fortress.ico"
$RegPath = "C:\\Users\\DELL\\Downloads\\Fortress\\fortress_filetype.reg"

Write-Host '[*] Applying registry entries...' -ForegroundColor Cyan
reg import $RegPath 2>&1 | Out-Null
cmd /c 'assoc .frt=FortressScript' 2>&1 | Out-Null

# Write HKCU user choice so it overrides for this user
$hkcu = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.frt'
New-Item -Path "$hkcu\OpenWithProgids" -Force | Out-Null
Set-ItemProperty -Path $hkcu -Name 'Progid' -Value 'FortressScript' -Force
New-ItemProperty -Path "$hkcu\OpenWithProgids" -Name 'FortressScript' -Value ([byte[]]@()) -PropertyType Binary -Force | Out-Null
$uc = "$hkcu\UserChoice"
if (Test-Path $uc) { Remove-Item $uc -Force }

# Nuke icon cache so Windows rebuilds it with new icon
Write-Host '[*] Clearing icon cache...' -ForegroundColor Yellow
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$icdb = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
Get-ChildItem $icdb -Filter iconcache*.db   -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem $icdb -Filter thumbcache*.db  -ErrorAction SilentlyContinue | Remove-Item -Force

# Notify shell
$sig = '[DllImport("Shell32.dll")] public static extern void SHChangeNotify(int e, uint f, IntPtr a, IntPtr b);'
Add-Type -MemberDefinition $sig -Name WinShell -Namespace Win32 -ErrorAction SilentlyContinue
try { [Win32.WinShell]::SHChangeNotify(0x08000000, 0x0000, [IntPtr]::Zero, [IntPtr]::Zero) } catch {}

Write-Host '[*] Restarting Explorer...' -ForegroundColor Yellow
Start-Process explorer.exe
Start-Sleep -Seconds 2

Write-Host ''
Write-Host '[+] Done!' -ForegroundColor Green
Write-Host '    Icon  -> Fortress hex icon' -ForegroundColor Green
Write-Host '    Type  -> Fortress Script (visible in Explorer Type column)' -ForegroundColor Green
Write-Host '    Open  -> Double-click runs with Fortress' -ForegroundColor Green
Write-Host ''
Write-Host 'If icon still missing: sign out and back in, or run: ie4uinit.exe -show' -ForegroundColor Yellow
pause

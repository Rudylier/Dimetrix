# Собирает Dimetrix.exe из src\Launcher.cs с иконкой app\Dimetrix.ico.
# Нужен только .NET Framework 4 — он есть в любой Windows 10/11.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
& $csc /nologo /target:winexe /codepage:65001 /optimize+ `
    "/win32icon:$root\app\Dimetrix.ico" `
    "/out:$root\Dimetrix.exe" `
    /reference:System.Windows.Forms.dll `
    "$root\src\Launcher.cs"
if ($LASTEXITCODE -ne 0) { throw "Сборка не удалась" }
Write-Host "Готово: $root\Dimetrix.exe"

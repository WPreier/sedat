# Helper: run cargo with a complete MSVC/Windows SDK environment.
$ErrorActionPreference = "Stop"
$msvcRoot = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
$sdkRoot = "C:\Program Files (x86)\Windows Kits\10"
$sdkVer = "10.0.26100.0"

$env:Path = "$msvcRoot\bin\HostX64\x64;$env:USERPROFILE\.cargo\bin;$env:Path"
$env:INCLUDE = @(
    "$msvcRoot\include",
    "$sdkRoot\Include\$sdkVer\ucrt",
    "$sdkRoot\Include\$sdkVer\um",
    "$sdkRoot\Include\$sdkVer\shared",
    "$sdkRoot\Include\$sdkVer\winrt"
) -join ";"
$env:LIB = @(
    "$msvcRoot\lib\x64",
    "$msvcRoot\lib\onecore\x64",
    "$sdkRoot\Lib\$sdkVer\ucrt\x64",
    "$sdkRoot\Lib\$sdkVer\um\x64"
) -join ";"

# Ensure legacy linker finds msvcrt via onecore if missing from lib\x64
if (-not (Test-Path "$msvcRoot\lib\x64\msvcrt.lib") -and (Test-Path "$msvcRoot\lib\onecore\x64\msvcrt.lib")) {
    Copy-Item "$msvcRoot\lib\onecore\x64\msvcrt.lib" "$msvcRoot\lib\x64\msvcrt.lib" -ErrorAction SilentlyContinue
}

Set-Location (Join-Path $PSScriptRoot "..")
& cargo @args
exit $LASTEXITCODE

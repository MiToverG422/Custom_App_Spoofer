param(
    [string]$SdkRoot = "",
    [string]$NdkVersion = "29.0.14206865",
    [string]$CMakeVersion = "3.31.10",
    [string]$BuildToolsVersion = "37.0.0",
    [string]$Version = "",
    [switch]$Ci,
    [switch]$Release,
    [string]$CMakeExe = "",
    [string]$NinjaExe = ""
)

& "$PSScriptRoot\scripts\build-module.ps1" `
    -SdkRoot $SdkRoot `
    -NdkVersion $NdkVersion `
    -CMakeVersion $CMakeVersion `
    -BuildToolsVersion $BuildToolsVersion `
    -Version $Version `
    -Ci:$Ci `
    -Release:$Release `
    -CMakeExe $CMakeExe `
    -NinjaExe $NinjaExe

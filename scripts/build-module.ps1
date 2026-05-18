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

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$ModulePropPath = Join-Path $Root "module\module.prop"

function Get-ModulePropValue {
    param(
        [Parameter(Mandatory = $true)][string]$Key
    )
    $line = Get-Content -LiteralPath $ModulePropPath -Encoding UTF8 |
        Where-Object { $_ -match "^$([regex]::Escape($Key))=" } |
        Select-Object -First 1
    if (-not $line) { return "" }
    return $line.Substring($Key.Length + 1).Trim()
}

function Get-BaseVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Value
    )
    if ($Value -match '^(v?\d+\.\d+\.\d+)') {
        return $Matches[1]
    }
    throw "Unable to derive base version from '$Value'. Expected vX.Y.Z or X.Y.Z."
}

function Test-VersionExists {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate
    )
    $localTag = (& git tag --list $Candidate 2>$null)
    if ($localTag) { return $true }
    return $false
}

function Get-ShortCommit {
    if ($env:GITHUB_SHA -match '^[0-9a-fA-F]{8,}$') {
        return $env:GITHUB_SHA.Substring(0, 8).ToLowerInvariant()
    }

    $short = (& git rev-parse --short=8 HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and $short -match '^[0-9a-fA-F]{7,}$') {
        return $short.Trim().Substring(0, [Math]::Min(8, $short.Trim().Length)).ToLowerInvariant()
    }

    throw "Unable to determine current Git commit short SHA."
}

function New-GitVersion {
    param(
        [Parameter(Mandatory = $true)][string]$BaseVersion,
        [Parameter(Mandatory = $true)][string]$Suffix
    )
    $candidate = "$BaseVersion-$(Get-ShortCommit)-$Suffix"
    if (Test-VersionExists -Candidate $candidate) {
        throw "Version '$candidate' already exists in local tags. Fetch tags before building, or build from a new commit."
    }
    return $candidate
}

function Get-AutoVersionCode {
    if ($env:GITHUB_RUN_NUMBER -match '^\d+$') {
        return [int](100000 + [int]$env:GITHUB_RUN_NUMBER)
    }
    return [int]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() % 2147483647)
}

function Set-ModuleVersion {
    param(
        [Parameter(Mandatory = $true)][string]$NewVersion,
        [Parameter(Mandatory = $true)][int]$NewVersionCode
    )
    $lines = Get-Content -LiteralPath $ModulePropPath -Encoding UTF8
    $lines = $lines | ForEach-Object {
        if ($_ -match '^version=') { "version=$NewVersion" }
        elseif ($_ -match '^versionCode=') { "versionCode=$NewVersionCode" }
        else { $_ }
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines((Resolve-Path -LiteralPath $ModulePropPath).Path, $lines, $utf8NoBom)
}

if (-not (Test-Path -LiteralPath $ModulePropPath)) { throw "module.prop not found: $ModulePropPath" }
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-ModulePropValue -Key "version"
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = "v0.1.0"
}
if ($Ci -and $Release) {
    throw "Use only one of -Ci or -Release."
}
if ($Ci) {
    $Version = New-GitVersion -BaseVersion (Get-BaseVersion -Value $Version) -Suffix "ci"
}
if ($Release) {
    $Version = New-GitVersion -BaseVersion (Get-BaseVersion -Value $Version) -Suffix "Releases"
}
$VersionCode = Get-AutoVersionCode
Set-ModuleVersion -NewVersion $Version -NewVersionCode $VersionCode

if ([string]::IsNullOrWhiteSpace($SdkRoot)) {
    if (-not [string]::IsNullOrWhiteSpace($env:ANDROID_HOME)) {
        $SdkRoot = $env:ANDROID_HOME
    }
    else {
        $SdkRoot = Join-Path $env:LOCALAPPDATA "Android\Sdk"
    }
}
$NdkRoot = Join-Path $SdkRoot "ndk\$NdkVersion"
if ([string]::IsNullOrWhiteSpace($CMakeExe)) {
    $SdkCMakeExe = Join-Path $SdkRoot "cmake\$CMakeVersion\bin\cmake.exe"
    if (Test-Path -LiteralPath $SdkCMakeExe) {
        $CMakeExe = $SdkCMakeExe
    }
    else {
        $CMakeCommand = Get-Command cmake -ErrorAction SilentlyContinue
        if ($CMakeCommand) { $CMakeExe = $CMakeCommand.Source }
    }
}
if ([string]::IsNullOrWhiteSpace($NinjaExe)) {
    $SdkNinjaExe = Join-Path $SdkRoot "cmake\$CMakeVersion\bin\ninja.exe"
    if (Test-Path -LiteralPath $SdkNinjaExe) {
        $NinjaExe = $SdkNinjaExe
    }
    else {
        $NinjaCommand = Get-Command ninja -ErrorAction SilentlyContinue
        if ($NinjaCommand) { $NinjaExe = $NinjaCommand.Source }
    }
}
$D8Exe = Join-Path $SdkRoot "build-tools\$BuildToolsVersion\d8.bat"
$StripExe = Join-Path $NdkRoot "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe"
$Toolchain = Join-Path $NdkRoot "build\cmake\android.toolchain.cmake"
$ModuleDir = Join-Path $Root "module"
$ZygiskDir = Join-Path $ModuleDir "zygisk"
$DistDir = Join-Path $Root "dist"
$BuildDir = Join-Path $Root "build"

if ([string]::IsNullOrWhiteSpace($CMakeExe) -or -not (Test-Path -LiteralPath $CMakeExe)) { throw "cmake.exe not found. Install CMake or pass -CMakeExe." }
if ([string]::IsNullOrWhiteSpace($NinjaExe) -or -not (Test-Path -LiteralPath $NinjaExe)) { throw "ninja.exe not found. Install Ninja or pass -NinjaExe." }
if (-not (Test-Path -LiteralPath $D8Exe)) { throw "d8.bat not found: $D8Exe" }
if (-not (Test-Path -LiteralPath $StripExe)) { throw "llvm-strip.exe not found: $StripExe" }
if (-not (Test-Path -LiteralPath $Toolchain)) { throw "Android NDK toolchain not found: $Toolchain" }

New-Item -ItemType Directory -Force -Path $ZygiskDir, $DistDir, $BuildDir | Out-Null
Get-ChildItem -LiteralPath $ZygiskDir -Filter *.so -ErrorAction SilentlyContinue | Remove-Item -Force

$HookerSrc = Join-Path $Root "hooker\src"
$HookerBuild = Join-Path $BuildDir "hooker"
$HookerClasses = Join-Path $HookerBuild "classes"
$HookerDexOut = Join-Path $HookerBuild "dex"
if (Test-Path -LiteralPath $HookerBuild) { Remove-Item -LiteralPath $HookerBuild -Recurse -Force }
New-Item -ItemType Directory -Force -Path $HookerClasses, $HookerDexOut | Out-Null
$HookerJava = Get-ChildItem -LiteralPath $HookerSrc -Recurse -Filter *.java | ForEach-Object { $_.FullName }
if (-not $HookerJava) { throw "No hooker Java sources found in $HookerSrc" }
& javac --release 8 -d $HookerClasses $HookerJava
if ($LASTEXITCODE -ne 0) { throw "javac failed for hooker dex" }
$HookerClassFiles = Get-ChildItem -LiteralPath $HookerClasses -Recurse -Filter *.class | ForEach-Object { $_.FullName }
if (-not $HookerClassFiles) { throw "No hooker class files were produced" }
& $D8Exe --min-api 26 --output $HookerDexOut $HookerClassFiles
if ($LASTEXITCODE -ne 0) { throw "d8 failed for hooker dex" }
$HookerDex = Join-Path $HookerDexOut "classes.dex"
if (-not (Test-Path -LiteralPath $HookerDex)) { throw "Hooker dex was not created: $HookerDex" }
Copy-Item -LiteralPath $HookerDex -Destination (Join-Path $ModuleDir "hooker.dex") -Force

$abis = @("arm64-v8a")
foreach ($abi in $abis) {
    $AbiBuild = Join-Path $BuildDir $abi
    & $CMakeExe `
        -S $Root `
        -B $AbiBuild `
        -G Ninja `
        "-DCMAKE_MAKE_PROGRAM=$NinjaExe" `
        "-DCMAKE_TOOLCHAIN_FILE=$Toolchain" `
        "-DANDROID_ABI=$abi" `
        "-DANDROID_PLATFORM=android-26" `
        "-DANDROID_STL=c++_static" `
        "-DCMAKE_BUILD_TYPE=Release"
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for $abi" }

    & $CMakeExe --build $AbiBuild --config Release
    if ($LASTEXITCODE -ne 0) { throw "CMake build failed for $abi" }

    $SoPath = Join-Path $AbiBuild "liboos_region_faker.so"
    if (-not (Test-Path -LiteralPath $SoPath)) { throw "Built library not found: $SoPath" }
    & $StripExe --strip-debug $SoPath
    if ($LASTEXITCODE -ne 0) { throw "llvm-strip failed for $abi" }
    Copy-Item -LiteralPath $SoPath -Destination (Join-Path $ZygiskDir "$abi.so") -Force
}

$Zip = Join-Path $DistDir "custom_app_spoofer-$Version.zip"
if (Test-Path -LiteralPath $Zip) { Remove-Item -LiteralPath $Zip -Force }

$TempPackage = Join-Path $BuildDir "package"
if (Test-Path -LiteralPath $TempPackage) { Remove-Item -LiteralPath $TempPackage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $TempPackage | Out-Null
Copy-Item -Path (Join-Path $ModuleDir "*") -Destination $TempPackage -Recurse -Force

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$ZipArchive = [System.IO.Compression.ZipFile]::Open($Zip, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    $BasePath = (Resolve-Path -LiteralPath $TempPackage).Path
    Get-ChildItem -LiteralPath $TempPackage -Recurse -File | ForEach-Object {
        $FullPath = $_.FullName
        $EntryName = $FullPath.Substring($BasePath.Length).TrimStart("\", "/") -replace "\\", "/"
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $ZipArchive,
            $FullPath,
            $EntryName,
            [System.IO.Compression.CompressionLevel]::Optimal
        ) | Out-Null
    }
}
finally {
    $ZipArchive.Dispose()
}
if (-not (Test-Path -LiteralPath $Zip)) { throw "Package zip was not created: $Zip" }
Write-Host "Built $Zip"
Write-Host "Version $Version ($VersionCode)"

if ($env:GITHUB_OUTPUT) {
    "version=$Version" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
    "version_code=$VersionCode" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
    "zip=$Zip" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
}

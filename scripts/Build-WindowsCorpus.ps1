# Copyright (c) NeverSight contributors.
# SPDX-License-Identifier: MIT

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("msvc", "clang-cl")]
  [string] $Toolchain,

  [Parameter(Mandatory = $true)]
  [ValidateSet("x86", "x86_64", "arm", "aarch64")]
  [string] $Architecture,

  [Parameter(Mandatory = $true)]
  [ValidateSet("o0", "o2")]
  [string] $Optimization,

  [Parameter(Mandatory = $true)]
  [ValidateSet("off", "on")]
  [string] $SecurityCookie,

  [Parameter(Mandatory = $true)]
  [ValidateSet("native", "fh3", "fh4")]
  [string] $CxxFormat,

  [Parameter(Mandatory = $true)]
  [string] $OutputRoot,

  [switch] $ValidateConfigurationOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ArchitectureMap = @{
  x86 = [ordered]@{
    target_triple = "i686-pc-windows-msvc"
    vs_arch = "x86"
    linker_machine = "X86"
    component = "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
    execute = $true
  }
  x86_64 = [ordered]@{
    target_triple = "x86_64-pc-windows-msvc"
    vs_arch = "x64"
    linker_machine = "X64"
    component = "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
    execute = $true
  }
  arm = [ordered]@{
    target_triple = "thumbv7-pc-windows-msvc"
    vs_arch = "arm"
    linker_machine = "ARM"
    component = "Microsoft.VisualStudio.Component.VC.Tools.ARM"
    execute = $false
  }
  aarch64 = [ordered]@{
    target_triple = "aarch64-pc-windows-msvc"
    vs_arch = "arm64"
    linker_machine = "ARM64"
    component = "Microsoft.VisualStudio.Component.VC.Tools.ARM64"
    execute = $false
  }
}

$Target = $ArchitectureMap[$Architecture]
$SupportedFormats = if ($Architecture -ne "x86_64") {
  @("native")
} elseif ($Toolchain -eq "msvc") {
  @("fh3", "fh4")
} else {
  @("fh3")
}
if ($CxxFormat -notin $SupportedFormats) {
  throw "unsupported C++ EH format '$CxxFormat' for $Toolchain/$Architecture"
}

$CookieLabel = if ($SecurityCookie -eq "on") { "gs" } else { "no-gs" }
$CellName = "$Toolchain-$Architecture-$CxxFormat-$CookieLabel-$Optimization"
$Compiler = if ($Toolchain -eq "msvc") { "cl.exe" } else { "clang-cl.exe" }
$Linker = if ($Toolchain -eq "msvc") { "link.exe" } else { "lld-link.exe" }
$OptimizationFlag = if ($Optimization -eq "o2") { "/O2" } else { "/Od" }
$SecurityFlag = if ($SecurityCookie -eq "on") { "/GS" } else { "/GS-" }
$CxxFormatFlag = $null
if ($Toolchain -eq "msvc" -and $Architecture -eq "x86_64") {
  $CxxFormatFlag = if ($CxxFormat -eq "fh4") { "/d2FH4" } else { "/d2FH4-" }
}

$CommonCompilerFlags = @(
  "/nologo",
  "/W4",
  "/Ob0",
  "/MD",
  $OptimizationFlag,
  $SecurityFlag,
  "/D_CRT_SECURE_NO_WARNINGS",
  "/DWIN32_LEAN_AND_MEAN",
  "/DWINVER=0x0601",
  "/D_WIN32_WINNT=0x0601"
)
if ($Toolchain -eq "clang-cl") {
  $CommonCompilerFlags += "--target=$($Target.target_triple)"
}

$CommonLinkerFlags = @(
  "/NOLOGO",
  "/INCREMENTAL:NO",
  "/BREPRO",
  "/MANIFEST:EMBED",
  "/DYNAMICBASE",
  "/NXCOMPAT",
  "/MACHINE:$($Target.linker_machine)",
  "kernel32.lib"
)
if ($Architecture -in @("x86_64", "aarch64")) {
  $CommonLinkerFlags += "/HIGHENTROPYVA"
}
if ($Optimization -eq "o2") {
  $CommonLinkerFlags += @("/OPT:REF", "/OPT:ICF")
} else {
  $CommonLinkerFlags += @("/OPT:NOREF", "/OPT:NOICF")
}

if ($ValidateConfigurationOnly) {
  [ordered]@{
    cell_name = $CellName
    toolchain = $Toolchain
    architecture = $Architecture
    target_triple = $Target.target_triple
    vs_arch = $Target.vs_arch
    linker_machine = $Target.linker_machine
    execute = $Target.execute
    compiler = $Compiler
    linker = $Linker
    cxx_format_flag = $CxxFormatFlag
    common_compiler_flags = @($CommonCompilerFlags)
    common_linker_flags = @($CommonLinkerFlags)
  } | ConvertTo-Json -Depth 5 -Compress
  exit 0
}

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$SourceRoot = Join-Path $RepositoryRoot "sources"
$OfficialSourceRoot = Join-Path $SourceRoot "windows-seh-tests/src"
$ProbeSourceRoot = Join-Path $SourceRoot "msvc-exceptions"
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$CellRelativeRoot = "corpus/windows-eh/$Toolchain/$Architecture/$CxxFormat/$CookieLabel/$Optimization"
$CellOutputRoot = Join-Path $OutputRoot $CellRelativeRoot
$OfficialOutputRoot = Join-Path $CellOutputRoot "windows-seh-tests"
$ProbeOutputRoot = Join-Path $CellOutputRoot "abi-probe"
$FragmentRoot = Join-Path $OutputRoot "fragments"
$BuildRoot = Join-Path ([IO.Path]::GetTempPath()) ("testbins-" + $CellName + "-" + [Guid]::NewGuid().ToString("N"))
$ArtifactSuffix = "$Toolchain-$Architecture-$CxxFormat-$CookieLabel-$Optimization"

function New-Directory([string] $Path) {
  [void](New-Item -ItemType Directory -Path $Path -Force)
}

function Import-VisualStudioEnvironment {
  if (-not $IsWindows) {
    throw "the Windows corpus builder requires Windows"
  }
  $VsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio/Installer/vswhere.exe"
  if (-not (Test-Path -LiteralPath $VsWhere -PathType Leaf)) {
    throw "vswhere.exe was not found"
  }
  $VsWhereArguments = @(
    "-latest",
    "-products", "*",
    "-requires", $Target.component,
    "-property", "installationPath"
  )
  $Installation = (& $VsWhere @VsWhereArguments | Select-Object -First 1)
  if (-not $Installation) {
    throw "a Visual Studio installation with $($Target.component) was not found"
  }
  $VsDevCmd = Join-Path $Installation "Common7/Tools/VsDevCmd.bat"
  if (-not (Test-Path -LiteralPath $VsDevCmd -PathType Leaf)) {
    throw "VsDevCmd.bat was not found in $Installation"
  }

  $VsDevCmdArguments = @(
    "-no_logo",
    "-arch=$($Target.vs_arch)",
    "-host_arch=x64"
  )
  $SdkLibraryDirectories = @()
  if ($Architecture -eq "arm") {
    $KitsLibraryRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits/10/Lib"
    $ArmSdk = Get-ChildItem -LiteralPath $KitsLibraryRoot -Directory |
      Where-Object {
        (Test-Path -LiteralPath (Join-Path $_.FullName "um/arm/kernel32.lib") -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $_.FullName "ucrt/arm/libucrt.lib") -PathType Leaf)
      } |
      Sort-Object { [version]$_.Name } -Descending |
      Select-Object -First 1
    if ($null -eq $ArmSdk) {
      throw "no installed Windows SDK contains ARM32 user-mode libraries"
    }
    $VsDevCmdArguments += "-winsdk=$($ArmSdk.Name)"
    $SdkLibraryDirectories = @(
      (Join-Path $ArmSdk.FullName "ucrt/arm"),
      (Join-Path $ArmSdk.FullName "um/arm")
    )
  }

  $EnvironmentCommand = "`"$VsDevCmd`" $($VsDevCmdArguments -join ' ') && set"
  $EnvironmentLines = & $env:ComSpec /s /c $EnvironmentCommand
  if ($LASTEXITCODE -ne 0) {
    throw "VsDevCmd.bat failed with exit code $LASTEXITCODE"
  }
  foreach ($Line in $EnvironmentLines) {
    if ($Line -match '^([^=]+)=(.*)$') {
      [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], "Process")
    }
  }
  if ($SdkLibraryDirectories.Count -ne 0) {
    $ExistingLibraries = if ($env:LIB) { @($env:LIB) } else { @() }
    $env:LIB = ($SdkLibraryDirectories + $ExistingLibraries) -join ";"
  }
  if ($env:VSCMD_ARG_TGT_ARCH -ne $Target.vs_arch) {
    throw "Visual Studio target architecture is '$env:VSCMD_ARG_TGT_ARCH', expected '$($Target.vs_arch)'"
  }
  [void](Get-Command $Compiler -CommandType Application -ErrorAction Stop)
  [void](Get-Command $Linker -CommandType Application -ErrorAction Stop)
  if ($Architecture -in @("arm", "aarch64")) {
    [void](Get-Command "llvm-readobj.exe" -CommandType Application -ErrorAction Stop)
  }
}

function Resolve-BuildTool([string] $CommandName) {
  if ($Toolchain -eq "clang-cl") {
    $StandaloneLLVM = Join-Path $env:ProgramFiles "LLVM/bin/$CommandName"
    if (Test-Path -LiteralPath $StandaloneLLVM -PathType Leaf) {
      return (Resolve-Path -LiteralPath $StandaloneLLVM).Path
    }
  }
  $Command = Get-Command $CommandName -CommandType Application -ErrorAction Stop |
    Select-Object -First 1
  return $Command.Source
}

function Invoke-Tool([string] $Tool, [string[]] $Arguments) {
  Write-Host "> $Tool $($Arguments -join ' ')"
  & $Tool @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$Tool failed with exit code $LASTEXITCODE"
  }
}

function Compile-Object(
  [string] $Source,
  [string] $Object,
  [string[]] $AdditionalFlags
) {
  $Arguments = @($script:CommonCompilerFlags) + $AdditionalFlags + @(
    "/c",
    $Source,
    "/Fo$Object"
  )
  Invoke-Tool $script:Compiler $Arguments
}

function Link-Image(
  [string] $Output,
  [string[]] $Objects,
  [string[]] $AdditionalFlags
) {
  $Arguments = @($script:CommonLinkerFlags) + $AdditionalFlags + @("/OUT:$Output") + $Objects
  Invoke-Tool $script:Linker $Arguments
}

function Invoke-Probe([string] $Executable, [string] $WorkingDirectory) {
  $Stdout = Join-Path $BuildRoot ((Split-Path -Leaf $Executable) + ".stdout.txt")
  $Stderr = Join-Path $BuildRoot ((Split-Path -Leaf $Executable) + ".stderr.txt")
  $ProcessArguments = @{
    FilePath = $Executable
    WorkingDirectory = $WorkingDirectory
    NoNewWindow = $true
    PassThru = $true
    RedirectStandardOutput = $Stdout
    RedirectStandardError = $Stderr
  }
  $Process = Start-Process @ProcessArguments
  if (-not $Process.WaitForExit(120000)) {
    $Process.Kill($true)
    throw "timed out while running $(Split-Path -Leaf $Executable)"
  }
  $Output = if (Test-Path -LiteralPath $Stdout) { Get-Content -LiteralPath $Stdout -Raw } else { "" }
  $Errors = if (Test-Path -LiteralPath $Stderr) { Get-Content -LiteralPath $Stderr -Raw } else { "" }
  if ($Output) { Write-Host $Output.TrimEnd() }
  if ($Errors) { Write-Host $Errors.TrimEnd() }
  if ($Process.ExitCode -ne 0) {
    throw "$(Split-Path -Leaf $Executable) exited with code $($Process.ExitCode)"
  }
}

function Get-ToolIdentity([string] $CommandPath) {
  $Command = Get-Command $CommandPath -CommandType Application -ErrorAction Stop |
    Select-Object -First 1
  $Version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Command.Source)
  $ProductVersion = [string]$Version.ProductVersion
  $FileVersion = [string]$Version.FileVersion
  if ([string]::IsNullOrWhiteSpace($ProductVersion)) {
    $ProductVersion = $FileVersion
  }
  if ([string]::IsNullOrWhiteSpace($FileVersion)) {
    $FileVersion = $ProductVersion
  }
  if ([string]::IsNullOrWhiteSpace($ProductVersion)) {
    throw "cannot determine the version of $($Command.Source)"
  }
  $Name = [IO.Path]::GetFileName($Command.Source)
  Write-Host "Using $Name $ProductVersion from $($Command.Source)"
  return [ordered]@{
    name = $Name
    product_version = $ProductVersion
    file_version = $FileVersion
  }
}

function Get-RepositoryRevision {
  $Revision = [Environment]::GetEnvironmentVariable("GITHUB_SHA")
  if ($Revision -notmatch '^[0-9a-fA-F]{40}$') {
    $Revision = (& git.exe -C $RepositoryRoot rev-parse HEAD | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0) {
      throw "git failed while reading the producer repository revision"
    }
  }
  if ($Revision -notmatch '^[0-9a-fA-F]{40}$') {
    throw "cannot determine the producer repository revision"
  }
  return $Revision.ToLowerInvariant()
}

function Get-ExpectedCxxPersonality {
  if ($Toolchain -eq "clang-cl") {
    return "__CxxFrameHandler3"
  }
  if ($CxxFormat -eq "fh4") {
    if ($SecurityCookie -eq "on") {
      return "__GSHandlerCheck_EH4"
    }
    return "__CxxFrameHandler4"
  }
  if ($SecurityCookie -eq "on") {
    return "__GSHandlerCheck_EH"
  }
  return "__CxxFrameHandler3"
}

function Get-ExpectedSEHPersonality {
  if ($Toolchain -eq "msvc" -and $SecurityCookie -eq "on") {
    return "__GSHandlerCheck_SEH"
  }
  return "__C_specific_handler"
}

function Get-NeverDExpectation([string] $Name, [string] $Kind) {
  if ($Architecture -eq "x86") {
    return [ordered]@{
      validation_level = "load-only"
      allowed_parse_status = @("complete")
      personalities_any = @()
      min_exception_functions = 0
      min_cxx_functions = 0
      min_try_blocks = 0
      min_seh_scopes = 0
    }
  }
  if ($Architecture -in @("arm", "aarch64")) {
    return [ordered]@{
      validation_level = "unwind-only"
      allowed_parse_status = @("complete", "partial")
      personalities_any = @()
      min_exception_functions = 1
      min_cxx_functions = 0
      min_try_blocks = 0
      min_seh_scopes = 0
    }
  }

  if ($Name -eq "cxx_eh_probe") {
    return [ordered]@{
      validation_level = "exception-graph"
      allowed_parse_status = @("complete")
      personalities_any = @(Get-ExpectedCxxPersonality)
      min_exception_functions = 1
      min_cxx_functions = 1
      min_try_blocks = 1
      min_seh_scopes = 0
    }
  }
  if ($Name -eq "seh_probe") {
    return [ordered]@{
      validation_level = "exception-graph"
      allowed_parse_status = @("complete")
      personalities_any = @(Get-ExpectedSEHPersonality)
      min_exception_functions = 1
      min_cxx_functions = 0
      min_try_blocks = 0
      min_seh_scopes = 1
    }
  }

  $Personalities = if ($Kind -eq "mixed") {
    @(
      "__C_specific_handler",
      "__GSHandlerCheck_SEH",
      "__CxxFrameHandler3",
      "__CxxFrameHandler4",
      "__GSHandlerCheck_EH",
      "__GSHandlerCheck_EH4"
    )
  } else {
    @("__C_specific_handler", "__GSHandlerCheck_SEH")
  }
  return [ordered]@{
    validation_level = "exception-graph"
    allowed_parse_status = @("complete")
    personalities_any = $Personalities
    min_exception_functions = 1
    min_cxx_functions = if ($Kind -eq "mixed") { 1 } else { 0 }
    min_try_blocks = if ($Kind -eq "mixed") { 1 } else { 0 }
    min_seh_scopes = 1
  }
}

function Get-Evidence([string] $Name, [string] $Kind) {
  if ($Architecture -eq "x86") {
    return [ordered]@{
      required_sections = @(".text")
      required_imports_any = @()
      require_exception_directory = $false
      require_unwind_records = $false
    }
  }
  if ($Architecture -in @("arm", "aarch64")) {
    return [ordered]@{
      required_sections = @(".pdata")
      required_imports_any = @()
      require_exception_directory = $true
      require_unwind_records = $true
    }
  }

  $ImportGroups = [Collections.Generic.List[object]]::new()
  if ($Name -eq "cxx_eh_probe") {
    $ImportGroups.Add(@(Get-ExpectedCxxPersonality))
  } elseif ($Name -eq "seh_probe") {
    $ImportGroups.Add(@(Get-ExpectedSEHPersonality))
  } elseif ($Kind -eq "mixed") {
    $ImportGroups.Add(@("__C_specific_handler", "__GSHandlerCheck_SEH"))
    $ImportGroups.Add(@(
      "__CxxFrameHandler3",
      "__CxxFrameHandler4",
      "__GSHandlerCheck_EH",
      "__GSHandlerCheck_EH4"
    ))
  } else {
    $ImportGroups.Add(@("__C_specific_handler", "__GSHandlerCheck_SEH"))
  }
  if ($SecurityCookie -eq "on" -and $Name -match "_probe$") {
    $ImportGroups.Add(@("__security_check_cookie"))
  }
  return [ordered]@{
    required_sections = @(".pdata")
    required_imports_any = @($ImportGroups)
    require_exception_directory = $true
    require_unwind_records = $true
  }
}

function Get-ArtifactPath([string] $Directory, [string] $Name, [string] $Extension) {
  return Join-Path $Directory "$Name-$ArtifactSuffix$Extension"
}

function New-ArtifactRecord(
  [string] $Path,
  [string] $Suite,
  [string] $Name,
  [string] $Kind,
  [string[]] $AdditionalCompilerFlags,
  [string[]] $AdditionalLinkerFlags
) {
  $Resolved = (Resolve-Path -LiteralPath $Path).Path
  $Relative = [IO.Path]::GetRelativePath($OutputRoot, $Resolved).Replace("\", "/")
  $File = Get-Item -LiteralPath $Resolved
  return [ordered]@{
    path = $Relative
    sha256 = (Get-FileHash -LiteralPath $Resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    size = [int64]$File.Length
    architecture = $Architecture
    suite = $Suite
    name = $Name
    kind = $Kind
    build = [ordered]@{
      toolchain = $Toolchain
      compiler = $script:CompilerIdentity
      linker = $script:LinkerIdentity
      target_triple = $Target.target_triple
      optimization = $Optimization
      security_cookie = ($SecurityCookie -eq "on")
      cxx_format = $CxxFormat
      execution = if ($Target.execute) { "passed" } else { "not-run-cross-target" }
      compiler_flags = @($script:CommonCompilerFlags + $AdditionalCompilerFlags)
      linker_flags = @($script:CommonLinkerFlags + $AdditionalLinkerFlags)
    }
    evidence = Get-Evidence $Name $Kind
    neverd = Get-NeverDExpectation $Name $Kind
  }
}

$script:Compiler = $Compiler
$script:Linker = $Linker
$script:CommonCompilerFlags = $CommonCompilerFlags
$script:CommonLinkerFlags = $CommonLinkerFlags

try {
  Import-VisualStudioEnvironment
  $script:Compiler = Resolve-BuildTool $Compiler
  $script:Linker = Resolve-BuildTool $Linker
  New-Directory $BuildRoot
  New-Directory $OfficialOutputRoot
  New-Directory $ProbeOutputRoot
  New-Directory $FragmentRoot

  $script:CompilerIdentity = Get-ToolIdentity $script:Compiler
  $script:LinkerIdentity = Get-ToolIdentity $script:Linker
  $Artifacts = [Collections.Generic.List[object]]::new()
  $CxxControlFlags = if ($null -ne $CxxFormatFlag) { @($CxxFormatFlag) } else { @() }

  $XcptObjects = @()
  foreach ($SourceName in @("xcpt4u.c", "xcpt4pg.c", "xcpt4ex.c")) {
    $Object = Join-Path $BuildRoot ($SourceName + ".obj")
    Compile-Object (Join-Path $OfficialSourceRoot "xcpt4/$SourceName") $Object @("/DBAIL_IN_FINALLY")
    $XcptObjects += $Object
  }
  $XcptCxxObject = Join-Path $BuildRoot "xcpt4cxx.obj"
  $XcptCxxFlags = @("/EHa") + $CxxControlFlags
  Compile-Object (Join-Path $OfficialSourceRoot "xcpt4/xcpt4cxx.cpp") $XcptCxxObject $XcptCxxFlags
  $XcptObjects += $XcptCxxObject
  $XcptOutput = Get-ArtifactPath $OfficialOutputRoot "xcpt4" ".exe"
  Link-Image $XcptOutput $XcptObjects @("/SUBSYSTEM:CONSOLE")

  $NestedObject = Join-Path $BuildRoot "nested_collided.obj"
  Compile-Object (Join-Path $OfficialSourceRoot "nested_collided/nestcol.c") $NestedObject @()
  $NestedOutput = Get-ArtifactPath $OfficialOutputRoot "nested_collided" ".exe"
  Link-Image $NestedOutput @($NestedObject) @("/SUBSYSTEM:CONSOLE")

  $XframeDllObject = Join-Path $BuildRoot "xframe_eh_dll.obj"
  $XframeDllSource = Join-Path $OfficialSourceRoot "xframe_eh_dll/xframe_eh_dll.c"
  $XframeDllCompilerFlags = @("/DWOWxframeEHDLL_EXPORTS", "/D_WINDOWS", "/D_USRDLL")
  Compile-Object $XframeDllSource $XframeDllObject $XframeDllCompilerFlags
  $XframeDllOutput = Get-ArtifactPath $OfficialOutputRoot "xframe_eh_dll" ".dll"
  $XframeDllImportLibrary = Join-Path $BuildRoot "xframe_eh_dll.lib"
  $DefinitionFile = Join-Path $OfficialSourceRoot "xframe_eh_dll/xframe_eh_dll.DEF"
  $XframeDllLinkerFlags = @(
    "/DLL",
    "/SUBSYSTEM:WINDOWS",
    "/DEF:$DefinitionFile",
    "/IMPLIB:$XframeDllImportLibrary"
  )
  Link-Image $XframeDllOutput @($XframeDllObject) $XframeDllLinkerFlags

  $XframeExeObject = Join-Path $BuildRoot "xframe_eh_exe.obj"
  Compile-Object (Join-Path $OfficialSourceRoot "xframe_eh_exe/xframe_eh_exe.c") $XframeExeObject @()
  $XframeExeOutput = Get-ArtifactPath $OfficialOutputRoot "xframe_eh_exe" ".exe"
  Link-Image $XframeExeOutput @($XframeExeObject) @("/SUBSYSTEM:CONSOLE")

  $SehProbeObject = Join-Path $BuildRoot "seh_probe.obj"
  Compile-Object (Join-Path $ProbeSourceRoot "seh_probe.c") $SehProbeObject @()
  $SehProbeOutput = Get-ArtifactPath $ProbeOutputRoot "seh_probe" ".exe"
  Link-Image $SehProbeOutput @($SehProbeObject) @("/SUBSYSTEM:CONSOLE")

  $CxxProbeObject = Join-Path $BuildRoot "cxx_eh_probe.obj"
  $CxxProbeFlags = @("/EHsc") + $CxxControlFlags
  Compile-Object (Join-Path $ProbeSourceRoot "cxx_eh_probe.cpp") $CxxProbeObject $CxxProbeFlags
  $CxxProbeOutput = Get-ArtifactPath $ProbeOutputRoot "cxx_eh_probe" ".exe"
  Link-Image $CxxProbeOutput @($CxxProbeObject) @("/SUBSYSTEM:CONSOLE")

  if ($Target.execute) {
    Invoke-Probe $XcptOutput $OfficialOutputRoot
    Invoke-Probe $NestedOutput $OfficialOutputRoot
    $RuntimeDllAlias = Join-Path $OfficialOutputRoot "xframe_eh_dll.dll"
    Copy-Item -LiteralPath $XframeDllOutput -Destination $RuntimeDllAlias
    try {
      Invoke-Probe $XframeExeOutput $OfficialOutputRoot
    } finally {
      Remove-Item -LiteralPath $RuntimeDllAlias -Force -ErrorAction SilentlyContinue
    }
    Invoke-Probe $SehProbeOutput $ProbeOutputRoot
    Invoke-Probe $CxxProbeOutput $ProbeOutputRoot
  } else {
    foreach ($ArtifactPath in @(
      $XcptOutput,
      $NestedOutput,
      $XframeDllOutput,
      $XframeExeOutput,
      $SehProbeOutput,
      $CxxProbeOutput
    )) {
      Invoke-Tool "llvm-readobj.exe" @("--unwind", $ArtifactPath)
    }
  }

  $Artifacts.Add((New-ArtifactRecord `
    -Path $XcptOutput `
    -Suite "windows-seh-tests" `
    -Name "xcpt4" `
    -Kind "mixed" `
    -AdditionalCompilerFlags (@("/DBAIL_IN_FINALLY") + $XcptCxxFlags) `
    -AdditionalLinkerFlags @("/SUBSYSTEM:CONSOLE")))
  $Artifacts.Add((New-ArtifactRecord `
    -Path $NestedOutput `
    -Suite "windows-seh-tests" `
    -Name "nested_collided" `
    -Kind "seh" `
    -AdditionalCompilerFlags @() `
    -AdditionalLinkerFlags @("/SUBSYSTEM:CONSOLE")))
  $Artifacts.Add((New-ArtifactRecord `
    -Path $XframeDllOutput `
    -Suite "windows-seh-tests" `
    -Name "xframe_eh_dll" `
    -Kind "seh" `
    -AdditionalCompilerFlags $XframeDllCompilerFlags `
    -AdditionalLinkerFlags @(
      "/DLL",
      "/SUBSYSTEM:WINDOWS",
      "/DEF:sources/windows-seh-tests/src/xframe_eh_dll/xframe_eh_dll.DEF"
    )))
  $Artifacts.Add((New-ArtifactRecord `
    -Path $XframeExeOutput `
    -Suite "windows-seh-tests" `
    -Name "xframe_eh_exe" `
    -Kind "seh" `
    -AdditionalCompilerFlags @() `
    -AdditionalLinkerFlags @("/SUBSYSTEM:CONSOLE")))
  $Artifacts.Add((New-ArtifactRecord `
    -Path $SehProbeOutput `
    -Suite "abi-probe" `
    -Name "seh_probe" `
    -Kind "seh" `
    -AdditionalCompilerFlags @() `
    -AdditionalLinkerFlags @("/SUBSYSTEM:CONSOLE")))
  $Artifacts.Add((New-ArtifactRecord `
    -Path $CxxProbeOutput `
    -Suite "abi-probe" `
    -Name "cxx_eh_probe" `
    -Kind "cxx" `
    -AdditionalCompilerFlags $CxxProbeFlags `
    -AdditionalLinkerFlags @("/SUBSYSTEM:CONSOLE")))

  $ImageOS = [Environment]::GetEnvironmentVariable("ImageOS")
  $ImageVersion = [Environment]::GetEnvironmentVariable("ImageVersion")
  $RunnerImage = if ($ImageOS) {
    if ($ImageVersion) { "$ImageOS-$ImageVersion" } else { $ImageOS }
  } else {
    "windows-2022"
  }
  $Fragment = [ordered]@{
    schema_version = 2
    corpus = "windows-eh"
    source = [ordered]@{
      windows_seh_tests = [ordered]@{
        repository = "https://github.com/microsoft/windows_seh_tests.git"
        revision = "2e8b7bb654d9aebf03f28801c4b1400489ba6a0c"
        license = "MIT"
      }
    }
    producer = [ordered]@{
      repository_revision = Get-RepositoryRevision
      runner_image = $RunnerImage
      runner_arch = "x64"
    }
    artifacts = @($Artifacts)
  }
  $FragmentPath = Join-Path $FragmentRoot ($CellName + ".json")
  $Fragment | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $FragmentPath -Encoding utf8NoBOM

  Invoke-Tool "python.exe" @(
    (Join-Path $PSScriptRoot "verify_windows_corpus.py"),
    $FragmentPath,
    "--root",
    $OutputRoot
  )
  Write-Host "Built and verified corpus cell $CellName"
} finally {
  if (Test-Path -LiteralPath $BuildRoot -PathType Container) {
    Remove-Item -LiteralPath $BuildRoot -Recurse -Force
  }
}

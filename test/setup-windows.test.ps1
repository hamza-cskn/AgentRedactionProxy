$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Run these tests on Windows.' }
$repo = Split-Path $PSScriptRoot -Parent
$setup = Join-Path $repo 'scripts/setup.ps1'
$pluginSource = Join-Path $repo '.opencode/plugins/openai-ipv4-proxy.js'
$configSource = Join-Path $repo 'examples/opencode.jsonc'

# Shadow every external operation. Tests never touch real Docker, credentials,
# user projects or the network, and need no administrator privileges.
function docker {
    $global:LASTEXITCODE = 0
    $s = $global:ArpSetupTestState
    $s.Commands.Add(@($args))
    switch ($args[0]) {
        'info' { if ($s.Failure -eq 'docker') { $global:LASTEXITCODE = 1 }; return }
        'pull' { if ($s.Failure -eq 'pull') { $global:LASTEXITCODE = 1 }; return }
        'inspect' {
            if (-not $s.Container) { $global:LASTEXITCODE = 1; return }
            ConvertTo-Json -InputObject @($s.Container) -Depth 10 -Compress
            return
        }
        'run' {
            if ($s.Failure -eq 'race') { $s.Container = Managed-Container; $s.Container.Config.Labels = @{}; $global:LASTEXITCODE = 1; return }
            $s.Container = Managed-Container
            $label = @($args | Where-Object { $_ -like 'io.agent-redaction-proxy.install-id=*' })[0]
            $s.Container.Config.Labels.'io.agent-redaction-proxy.install-id' = $label.Split('=')[1]
            return 'test-container'
        }
        'start' { $s.Container.State.Running = $true; return }
        'stop' { $s.Container.State.Running = $false; return }
        'rm' { $s.Container = $null; return }
        'exec' { if ($s.Failure -eq 'probe') { $global:LASTEXITCODE = 1 }; return }
        default { throw 'Unexpected Docker command in test.' }
    }
}
function opencode {
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'auth') {
        if ($global:ArpSetupTestState.Failure -eq 'auth') { return 'OpenAI api' }
        return 'OpenAI oauth'
    }
    if ($global:ArpSetupTestState.Failure -eq 'models') { return }
    if ($global:ArpSetupTestState.Failure -eq 'models-exit') { $global:LASTEXITCODE = 1 }
    return 'openai/test-model'
}
function Start-Sleep { param($Seconds) }
function Invoke-WebRequest {
    param($Uri, [switch]$UseBasicParsing, $OutFile)
    if ($global:ArpSetupTestState.Failure -eq 'download') { throw 'Mock download failed.' }
    $source = if ($Uri -like '*/plugins/*') { $pluginSource } else { $configSource }
    # Git may check fixtures out as CRLF on Windows; GitHub raw downloads are LF.
    [IO.File]::WriteAllText($OutFile, [IO.File]::ReadAllText($source).Replace("`r`n", "`n"), [Text.UTF8Encoding]::new($false))
    if ($global:ArpSetupTestState.Failure -eq 'checksum') { [IO.File]::AppendAllText($OutFile, 'modified') }
}
function Managed-Container {
    return @{
        Config = @{ Image = '366366/agent-redaction-proxy:latest'; Labels = @{
            'io.agent-redaction-proxy.managed' = '1'; 'io.agent-redaction-proxy.install-id' = 'existing' } }
        State = @{ Running = $true }
        Mounts = @(@{ Type = 'volume'; Destination = '/data'; Name = 'agent-redaction-proxy-data' })
        HostConfig = @{ PortBindings = @{
            '8787/tcp' = @(@{ HostIp = '127.0.0.1'; HostPort = '8787' })
            '8788/tcp' = @(@{ HostIp = '127.0.0.1'; HostPort = '8788' }) } }
    }
}
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
function Run-Setup($Action = 'install', [switch]$Fails) {
    $failed = $false
    try { & $setup $Action } catch { if (-not $Fails) { throw }; $failed = $true }
    Assert ($failed -eq [bool]$Fails) "Unexpected setup outcome: $Action, failure=$failed"
}
function Run-Case($Name, [scriptblock]$Body) {
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('arp-windows-' + [Guid]::NewGuid().ToString('N'))
    $project = Join-Path $directory 'project with spaces'
    [IO.Directory]::CreateDirectory($project) | Out-Null
    $global:ArpSetupTestState = @{ Container = $null; Commands = [Collections.Generic.List[object]]::new(); Failure = '' }
    Push-Location $project
    try { & $Body; Write-Host "PASS: $Name" }
    finally { Pop-Location; Remove-Item -LiteralPath $directory -Recurse -Force }
}

Run-Case 'install, repeat and uninstall preserve shared proxy and mappings' {
    Run-Setup
    Assert (Test-Path '.opencode/plugins/openai-ipv4-proxy.js') 'Plugin missing.'
    Assert (Test-Path 'opencode.jsonc') 'Config missing.'
    Assert ((Get-Acl '.opencode/.agent-redaction-proxy-install').AreAccessRulesProtected) 'Receipt ACL is not private.'
    Run-Setup
    Assert (@($global:ArpSetupTestState.Commands | Where-Object { $_[0] -eq 'run' }).Count -eq 1) 'Container was recreated.'
    $run = @($global:ArpSetupTestState.Commands | Where-Object { $_[0] -eq 'run' })[0]
    Assert ($run -contains '127.0.0.1:8787:8787') 'Non-local port binding.'
    Assert ($run -contains 'agent-redaction-proxy-data:/data') 'Mapping volume missing.'
    Run-Setup 'uninstall'
    Assert (-not (Test-Path '.opencode/plugins/openai-ipv4-proxy.js')) 'Plugin not removed.'
    Assert (-not (Test-Path 'opencode.jsonc')) 'Config not removed.'
    Assert $global:ArpSetupTestState.Container.State.Running 'Shared container stopped.'
    Assert (@($global:ArpSetupTestState.Commands | Where-Object { $_[0] -in @('rm', 'stop', 'volume') }).Count -eq 0) 'Shared storage/container modified.'
    Run-Setup 'uninstall'
}
Run-Case 'download-and-execute install and parameterized uninstall' {
    $source = [IO.File]::ReadAllText($setup)
    Invoke-Expression $source
    Assert (Test-Path '.opencode/plugins/openai-ipv4-proxy.js') 'Bootstrap did not install.'
    & ([scriptblock]::Create($source)) uninstall
    Assert (-not (Test-Path '.opencode/plugins/openai-ipv4-proxy.js')) 'Bootstrap did not uninstall.'
}
Run-Case 'incomplete download cannot start setup' {
    $source = [IO.File]::ReadAllText($setup)
    $failed = $false
    try { Invoke-Expression $source.Substring(0, $source.LastIndexOf('} @args')) } catch { $failed = $true }
    Assert $failed 'Incomplete script parsed successfully.'
    Assert (@(Get-ChildItem -Force).Count -eq 0) 'Incomplete script changed project files.'
    Assert ($global:ArpSetupTestState.Commands.Count -eq 0) 'Incomplete script invoked external commands.'
}
foreach ($name in @('opencode.json', 'opencode.jsonc')) {
    Run-Case "preserve existing $name" {
        [IO.File]::WriteAllText((Join-Path (Get-Location).Path $name), '{ // preserve comments and bytes }')
        Run-Setup
        Run-Setup 'uninstall'
        Assert ([IO.File]::ReadAllText((Join-Path (Get-Location).Path $name)) -eq '{ // preserve comments and bytes }') 'Existing config changed.'
        if ($name -eq 'opencode.json') { Assert (-not (Test-Path 'opencode.jsonc')) 'Competing config created.' }
    }
}
foreach ($target in @('.opencode/plugins/openai-ipv4-proxy.js', 'opencode.jsonc')) {
    Run-Case "preserve modified $target" {
        Run-Setup
        [IO.File]::AppendAllText((Join-Path (Get-Location).Path $target), 'user modification')
        Run-Setup 'uninstall' -Fails
        Assert (Test-Path '.opencode/plugins/openai-ipv4-proxy.js') 'Plugin removed despite conflict.'
        Assert (Test-Path 'opencode.jsonc') 'Config removed despite conflict.'
    }
}
foreach ($failure in @('docker', 'auth', 'download', 'checksum', 'pull', 'models', 'models-exit', 'probe', 'race')) {
    Run-Case "rollback $failure" {
        $global:ArpSetupTestState.Failure = $failure
        Run-Setup -Fails
        Assert (@(Get-ChildItem -Force).Count -eq 0) 'Rollback left project files behind.'
        if ($failure -eq 'race') { Assert ($null -ne $global:ArpSetupTestState.Container) 'Concurrent container was removed.' }
        else { Assert ($null -eq $global:ArpSetupTestState.Container) 'New container was not removed.' }
    }
}
Run-Case 'unmanaged plugin remains untouched' {
    New-Item -ItemType Directory '.opencode/plugins' | Out-Null
    [IO.File]::WriteAllText((Join-Path (Get-Location).Path '.opencode/plugins/openai-ipv4-proxy.js'), 'user plugin')
    Run-Setup -Fails
    Run-Setup 'uninstall'
    Assert ([IO.File]::ReadAllText((Join-Path (Get-Location).Path '.opencode/plugins/openai-ipv4-proxy.js')) -eq 'user plugin') 'Unmanaged plugin changed.'
}
Run-Case 'stopped managed container restored on failure' {
    $global:ArpSetupTestState.Container = Managed-Container
    $global:ArpSetupTestState.Container.State.Running = $false
    $global:ArpSetupTestState.Failure = 'models'
    Run-Setup -Fails
    Assert (-not $global:ArpSetupTestState.Container.State.Running) 'Stopped container was not restored.'
}
foreach ($conflict in @('label', 'image', 'volume', 'port')) {
    Run-Case "existing container conflict: $conflict" {
        $c = Managed-Container
        switch ($conflict) {
            'label' { $c.Config.Labels = @{} }
            'image' { $c.Config.Image = 'another-image' }
            'volume' { $c.Mounts[0].Name = 'another-volume' }
            'port' { $c.HostConfig.PortBindings.'8787/tcp'[0].HostIp = '0.0.0.0' }
        }
        $global:ArpSetupTestState.Container = $c
        Run-Setup -Fails
        Assert (@(Get-ChildItem -Force).Count -eq 0) 'Conflict left project files.'
        Assert (@($global:ArpSetupTestState.Commands | Where-Object { $_[0] -in @('rm', 'start', 'stop') }).Count -eq 0) 'Conflicting container changed.'
    }
}
Run-Case 'foreign setup lock preserved' {
    New-Item -ItemType Directory '.opencode/.agent-redaction-proxy-setup.lock' | Out-Null
    Run-Setup -Fails
    Assert (Test-Path '.opencode/.agent-redaction-proxy-setup.lock') 'Foreign lock removed.'
}
Run-Case 'junction integration path rejected' {
    $outside = Join-Path (Split-Path (Get-Location).Path -Parent) 'outside'
    New-Item -ItemType Directory $outside | Out-Null
    [IO.File]::WriteAllText((Join-Path $outside 'keep'), 'user data')
    New-Item -ItemType Junction -Path '.opencode' -Target $outside | Out-Null
    Run-Setup -Fails
    Assert ([IO.File]::ReadAllText((Join-Path $outside 'keep')) -eq 'user data') 'Junction target changed.'
    [IO.Directory]::Delete((Join-Path (Get-Location).Path '.opencode'))
}
Write-Host 'All Windows installer tests passed.'

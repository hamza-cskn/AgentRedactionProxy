# Keep execution inside one script block so incomplete downloads cannot run setup.
& {
    param([ValidateSet('install', 'uninstall')][string]$Action = 'install')
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 2
    if ($args.Count -gt 0) { throw 'Usage: setup.ps1 [install|uninstall]' }
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Use setup.sh on macOS/Linux.' }
    if ((Get-Location).Provider.Name -ne 'FileSystem') { throw 'Go to your project directory first.' }
    $project = (Get-Location).Path
    if ($project -eq [IO.Path]::GetPathRoot($project) -or $project -eq $env:USERPROFILE) {
        throw 'Go to your project directory before running setup.'
    }
    $opencodeDir = Join-Path $project '.opencode'
    $plugins = Join-Path $opencodeDir 'plugins'
    $plugin = Join-Path $plugins 'openai-ipv4-proxy.js'
    $config = Join-Path $project 'opencode.jsonc'
    $jsonConfig = Join-Path $project 'opencode.json'
    $receipt = Join-Path $opencodeDir '.agent-redaction-proxy-install'
    $lock = Join-Path $opencodeDir '.agent-redaction-proxy-setup.lock'
    $pluginReference = Join-Path $receipt 'plugin.reference'
    $configReference = Join-Path $receipt 'config.reference'
    $image = '366366/agent-redaction-proxy:latest'
    $container = 'agent-redaction-proxy'
    $volume = 'agent-redaction-proxy-data'
    $source = 'https://raw.githubusercontent.com/hamza-cskn/AgentRedactionProxy/9bc1edbe0de7df4f11423d53fbef61972cd155cd'
    $pluginCreated = $configCreated = $receiptCreated = $lockCreated = $false
    $opencodeCreated = $pluginsCreated = $containerCreated = $containerStarted = $false
    $completed = $false
    $installId = [Guid]::NewGuid().ToString('N')

    function Same-File($Left, $Right) {
        return (Test-Path -LiteralPath $Left -PathType Leaf) -and
            (Test-Path -LiteralPath $Right -PathType Leaf) -and
            ((Get-FileHash -LiteralPath $Left -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $Right -Algorithm SHA256).Hash)
    }
    function Assert-SafePath($Path) {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Setup paths must not be symbolic links or junctions.'
        }
    }
    function Invoke-Native([string]$Command, [string[]]$Arguments, [switch]$AllowFailure) {
        # Native exit codes must be checked explicitly, including PowerShell 5.1.
        $ErrorActionPreference = 'Continue'
        $global:LASTEXITCODE = 0
        $output = & $Command @Arguments 2>&1
        $code = $LASTEXITCODE
        if ($code -ne 0 -and -not $AllowFailure) { throw "$Command $($Arguments[0]) failed." }
        return [PSCustomObject]@{ Code = $code; Text = ($output | Out-String).Trim() }
    }
    function Inspect-Container {
        $result = Invoke-Native docker @('inspect', $container) -AllowFailure
        if ($result.Code -eq 0) { return @($result.Text | ConvertFrom-Json)[0] }
        return $null
    }
    function Container-Label($Info, $Name) {
        if ($Info -and $Info.Config.Labels) {
            $property = $Info.Config.Labels.PSObject.Properties[$Name]
            if ($property) { return $property.Value }
        }
        return $null
    }
    function Download-Checked($Url, $Destination, $Hash) {
        # Basic parsing avoids Internet Explorer and downloaded HTML execution.
        Invoke-WebRequest -Uri $Url -UseBasicParsing -OutFile $Destination | Out-Null
        if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -ne $Hash) {
            throw 'Download checksum mismatch. Nothing installed.'
        }
    }
    function Remove-EmptyDirectory($Path) {
        if (Test-Path -LiteralPath $Path) { [IO.Directory]::Delete($Path, $false) }
    }

    foreach ($file in @($opencodeDir, $plugins, $receipt, $lock, $plugin, $config, $jsonConfig)) { Assert-SafePath $file }
    if ($Action -eq 'uninstall' -and -not (Test-Path -LiteralPath $receipt)) {
        Write-Host 'No managed installation in this project. Nothing changed.'
        return
    }
    try {
        if (-not (Test-Path -LiteralPath $opencodeDir)) {
            New-Item -ItemType Directory -Path $opencodeDir | Out-Null
            $opencodeCreated = $true
        }
        try { New-Item -ItemType Directory -Path $lock | Out-Null }
        catch { throw 'Another setup is running, or a setup lock remains. Nothing changed.' }
        $lockCreated = $true
        if (Test-Path -LiteralPath $receipt) {
            if (-not (Test-Path -LiteralPath $receipt -PathType Container) -or
                -not (Test-Path -LiteralPath $pluginReference -PathType Leaf)) { throw 'Invalid installation receipt.' }
            foreach ($file in Get-ChildItem -LiteralPath $receipt -Force) {
                Assert-SafePath $file.FullName
                if ($file.PSIsContainer -or $file.Name -cnotin @('plugin.reference', 'config.reference')) {
                    throw 'Unexpected receipt files; refusing to modify files.'
                }
            }
            if ((Test-Path -LiteralPath $plugin) -and -not (Same-File $plugin $pluginReference)) {
                throw 'Installed plugin was modified; keep it or remove it manually.'
            }
            if ((Test-Path -LiteralPath $configReference) -and (Test-Path -LiteralPath $config) -and
                -not (Same-File $config $configReference)) { throw 'Installed config was modified; keep it or remove it manually.' }
        } elseif (Test-Path -LiteralPath $plugin) {
            throw 'An existing plugin is not managed by this installer. It will not be overwritten.'
        }
        if ($Action -eq 'uninstall') {
            if (Test-Path -LiteralPath $plugin) { Remove-Item -LiteralPath $plugin }
            if ((Test-Path -LiteralPath $configReference) -and (Test-Path -LiteralPath $config)) { Remove-Item -LiteralPath $config }
            foreach ($file in @($pluginReference, $configReference)) {
                if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
            }
            Remove-EmptyDirectory $receipt
            $completed = $true
            Write-Host 'Project integration removed. Shared proxy, credentials and mapping data were preserved.'
            return
        }
        foreach ($command in @('docker', 'opencode')) {
            if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "Install $command first." }
        }
        Invoke-Native docker @('info') | Out-Null
        $auth = Invoke-Native opencode @('auth', 'list', '--pure')
        if ($auth.Text -notmatch '(?i)OpenAI.*oauth') { throw 'Sign in first: opencode auth login --provider openai --pure' }
        if (-not (Test-Path -LiteralPath $receipt)) {
            New-Item -ItemType Directory -Path $receipt | Out-Null
            $receiptCreated = $true
            $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $acl = New-Object Security.AccessControl.DirectorySecurity
            $acl.SetOwner($sid)
            $acl.SetAccessRuleProtection($true, $false)
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
            Set-Acl -LiteralPath $receipt -AclObject $acl
            Download-Checked "$source/.opencode/plugins/openai-ipv4-proxy.js" $pluginReference '2ea1afe96670ab0d994e6f1e4ed45c10962361e8f7851ec8db9a776f4b423b28'
            if (-not (Test-Path -LiteralPath $config) -and -not (Test-Path -LiteralPath $jsonConfig)) {
                Download-Checked "$source/examples/opencode.jsonc" $configReference '2b5b98a5f7d694cc699280a0d072030cae33c24819d294a5c36e57f90e48917e'
            }
        }
        $existing = Inspect-Container
        if ($existing) {
            if ((Container-Label $existing 'io.agent-redaction-proxy.managed') -ne '1') { throw 'An unmanaged container already uses this name.' }
            if ($existing.Config.Image -ne $image) { throw 'Existing container uses a different image.' }
            $mount = @($existing.Mounts | Where-Object { $_.Destination -eq '/data' })
            if ($mount.Count -ne 1 -or $mount[0].Type -ne 'volume' -or $mount[0].Name -ne $volume) { throw 'Existing container uses different mapping storage.' }
            foreach ($port in @('8787', '8788')) {
                $bindings = @($existing.HostConfig.PortBindings."$port/tcp")
                if ($bindings.Count -ne 1 -or $bindings[0].HostIp -ne '127.0.0.1' -or $bindings[0].HostPort -ne $port) { throw 'Existing container uses different port bindings.' }
            }
            if (-not $existing.State.Running) {
                Invoke-Native docker @('start', $container) | Out-Null
                $containerStarted = $true
            }
        } else {
            Invoke-Native docker @('pull', $image) | Out-Null
            $containerCreated = $true
            Invoke-Native docker @('run', '-d', '--name', $container, '--init', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--label', 'io.agent-redaction-proxy.managed=1', '--label', "io.agent-redaction-proxy.install-id=$installId",
                '-p', '127.0.0.1:8787:8787', '-p', '127.0.0.1:8788:8788', '-v', "${volume}:/data", '--tmpfs', '/tmp:size=16m,mode=1777', $image) | Out-Null
        }
        $probe = 'const net=require(''node:net'');Promise.all([8787,8788].map(port=>new Promise((resolve,reject)=>{const s=net.connect(port,''127.0.0.1'');s.setTimeout(1000);s.once(''connect'',()=>{s.destroy();resolve();});s.once(''error'',reject);s.once(''timeout'',()=>{s.destroy();reject();});}))).then(()=>process.exit(0),()=>process.exit(1))'
        $ready = $false
        for ($attempt = 0; $attempt -lt 15; $attempt++) {
            if ((Invoke-Native docker @('exec', $container, 'node', '-e', $probe) -AllowFailure).Code -eq 0) { $ready = $true; break }
            Start-Sleep -Seconds 1
        }
        if (-not $ready) { throw 'Proxy listeners did not start. No project integration was installed.' }
        if (-not (Test-Path -LiteralPath $plugins)) {
            New-Item -ItemType Directory -Path $plugins | Out-Null
            $pluginsCreated = $true
        }
        # Same-volume File.Move is exclusive: never overwrite a concurrent file.
        if (-not (Test-Path -LiteralPath $plugin)) {
            $staged = Join-Path $receipt 'plugin.staged'
            [IO.File]::Copy($pluginReference, $staged, $false)
            [IO.File]::Move($staged, $plugin)
            $pluginCreated = $true
        }
        if ((Test-Path -LiteralPath $configReference) -and -not (Test-Path -LiteralPath $config) -and -not (Test-Path -LiteralPath $jsonConfig)) {
            $staged = Join-Path $receipt 'config.staged'
            [IO.File]::Copy($configReference, $staged, $false)
            [IO.File]::Move($staged, $config)
            $configCreated = $true
        }
        $models = Invoke-Native opencode @('models', 'openai')
        if ($models.Text -notmatch '(?m)^openai/') { throw 'Your existing configuration disables OpenAI models.' }
        $completed = $true
        Write-Host 'Ready. Restart OpenCode in this project and select an OpenAI model with /models.'
    } finally {
        if (-not $completed -and $Action -eq 'install') {
            try {
                if ($pluginCreated -and (Same-File $plugin $pluginReference)) { Remove-Item -LiteralPath $plugin }
                if ($configCreated -and (Same-File $config $configReference)) { Remove-Item -LiteralPath $config }
                if ($containerCreated) {
                    $created = Inspect-Container
                    if ((Container-Label $created 'io.agent-redaction-proxy.install-id') -eq $installId) {
                        Invoke-Native docker @('rm', '-f', $container) | Out-Null
                    }
                } elseif ($containerStarted) { Invoke-Native docker @('stop', $container) | Out-Null }
            } catch { Write-Warning 'Rollback could not restore every file/container; inspect this installation manually.' }
            if ($receiptCreated) {
                foreach ($name in @('plugin.reference', 'config.reference', 'plugin.staged', 'config.staged')) {
                    try { Remove-Item -LiteralPath (Join-Path $receipt $name) -ErrorAction SilentlyContinue } catch { Write-Warning 'Could not clean up an installation receipt file.' }
                }
                try { Remove-EmptyDirectory $receipt } catch { Write-Warning 'Could not remove the installation receipt directory.' }
            }
            if ($pluginsCreated) { try { Remove-EmptyDirectory $plugins } catch { Write-Warning 'Plugin directory is not empty; preserved it.' } }
        }
        if ($lockCreated) { try { Remove-EmptyDirectory $lock } catch { Write-Warning 'Could not remove setup lock; inspect it manually.' } }
        if (-not $completed -and $opencodeCreated) { try { Remove-EmptyDirectory $opencodeDir } catch { Write-Warning 'Project integration directory is not empty; preserved it.' } }
    }
} @args

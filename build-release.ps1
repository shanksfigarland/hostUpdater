$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$output = Join-Path $root 'dist'

New-Item -ItemType Directory -Force -Path $output | Out-Null

$targets = @(
    @{ Arch = 'amd64'; Name = 'hostupdater-linux-amd64' },
    @{ Arch = 'arm64'; Name = 'hostupdater-linux-arm64' }
)

foreach ($target in $targets) {
    $env:GOOS = 'linux'
    $env:GOARCH = $target.Arch
    $binary = Join-Path $output $target.Name
    go build -trimpath -ldflags='-s -w' -o $binary .
}

Get-ChildItem -LiteralPath $output -Filter 'hostupdater-linux-*' |
    Get-FileHash -Algorithm SHA256 |
    ForEach-Object { '{0}  {1}' -f $_.Hash.ToLowerInvariant(), (Split-Path -Leaf $_.Path) } |
    Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS') -Encoding ascii

Get-ChildItem -LiteralPath $output | Select-Object Name, Length

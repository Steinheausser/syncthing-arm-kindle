# Reproducible build of Syncthing v2.1.2 for linux/arm (Kindle) with
# ARMv8-AArch32 hardware SHA-256 + NEON ChaCha20 + ARMv7 Poly1305 patched
# into Go's stdlib via `go build -overlay` (installed Go is untouched).
#
# Usage: powershell -ExecutionPolicy Bypass -File build.ps1 [-SkipSyncthing]
param([switch]$SkipSyncthing)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$env:Path = "$env:USERPROFILE\scoop\apps\go\current\bin;$env:USERPROFILE\scoop\shims;" + $env:Path

function Run($exe, [string[]]$a) {
    Write-Host "> $exe $($a -join ' ')"
    & $exe @a
    if ($LASTEXITCODE -ne 0) { throw "$exe failed with exit code $LASTEXITCODE" }
}

$goroot = (& go env GOROOT).Trim()
Write-Host "Go: $(& go version)  GOROOT=$goroot"
Write-Host "zig: $(& zig version)"

# 1. Generate the assembly files (assembled by zig's clang).
$ov = Join-Path $here 'overlay'
$shaDir    = Join-Path $ov 'crypto\internal\fips140\sha256'
$cpuDir    = Join-Path $ov 'crypto\internal\fips140deps\cpu'
$chachaDir = Join-Path $ov 'vendor\golang.org\x\crypto\chacha20'
$polyDir   = Join-Path $ov 'vendor\golang.org\x\crypto\internal\poly1305'
New-Item -ItemType Directory -Force $shaDir, $cpuDir, $chachaDir, $polyDir | Out-Null
Run python @('-I', (Join-Path $here 'gen_asm.py'), $ov)

# 2. Patched copies of *_noasm.go: exclude arm from the generic stubs.
function PatchNoAsm($relPath, $oldConstraint, $newConstraint, $dstPath) {
    $srcPath = Join-Path $goroot $relPath
    $txt = [IO.File]::ReadAllText($srcPath)
    if (-not $txt.Contains($oldConstraint)) {
        throw "unexpected build constraint in $srcPath"
    }
    $txt = $txt.Replace($oldConstraint, $newConstraint)
    [IO.File]::WriteAllText($dstPath, $txt, (New-Object Text.UTF8Encoding $false))
}

PatchNoAsm 'src\crypto\internal\fips140\sha256\sha256block_noasm.go' `
    '!amd64 && !arm64' '!amd64 && !arm && !arm64' `
    (Join-Path $shaDir 'sha256block_noasm.go')

PatchNoAsm 'src\vendor\golang.org\x\crypto\chacha20\chacha_noasm.go' `
    '!arm64 && !s390x' '!arm && !arm64 && !s390x' `
    (Join-Path $chachaDir 'chacha_noasm.go')

PatchNoAsm 'src\vendor\golang.org\x\crypto\internal\poly1305\mac_noasm.go' `
    '!amd64 && !loong64' '!amd64 && !arm && !loong64' `
    (Join-Path $polyDir 'mac_noasm.go')

# 3. overlay.json (maps GOROOT paths -> our overlay files).
$map = [ordered]@{}
$map[(Join-Path $goroot 'src\crypto\internal\fips140\sha256\sha256block_noasm.go')] = (Join-Path $shaDir 'sha256block_noasm.go')
$map[(Join-Path $goroot 'src\crypto\internal\fips140\sha256\sha256block_arm.go')]   = (Join-Path $shaDir 'sha256block_arm.go')
$map[(Join-Path $goroot 'src\crypto\internal\fips140\sha256\sha256block_arm.s')]    = (Join-Path $shaDir 'sha256block_arm.s')
$map[(Join-Path $goroot 'src\crypto\internal\fips140deps\cpu\cpu_arm.go')]          = (Join-Path $cpuDir 'cpu_arm.go')
$map[(Join-Path $goroot 'src\vendor\golang.org\x\crypto\chacha20\chacha_noasm.go')] = (Join-Path $chachaDir 'chacha_noasm.go')
$map[(Join-Path $goroot 'src\vendor\golang.org\x\crypto\chacha20\chacha_arm.go')]   = (Join-Path $chachaDir 'chacha_arm.go')
$map[(Join-Path $goroot 'src\vendor\golang.org\x\crypto\chacha20\chacha_arm.s')]    = (Join-Path $chachaDir 'chacha_arm.s')
$map[(Join-Path $goroot 'src\vendor\golang.org\x\crypto\internal\poly1305\mac_noasm.go')] = (Join-Path $polyDir 'mac_noasm.go')
$map[(Join-Path $goroot 'src\vendor\golang.org\x\crypto\internal\poly1305\sum_arm.go')]   = (Join-Path $polyDir 'sum_arm.go')
$map[(Join-Path $goroot 'src\vendor\golang.org\x\crypto\internal\poly1305\sum_arm.s')]    = (Join-Path $polyDir 'sum_arm.s')

$overlayJson = Join-Path $here 'overlay.json'
[IO.File]::WriteAllText($overlayJson, (@{ Replace = $map } | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))

# 4. Build test binary (pure Go, no cgo).
$env:GOOS = 'linux'; $env:GOARCH = 'arm'; $env:GOARM = '7'; $env:CGO_ENABLED = '0'
$out = Join-Path $here 'out'
New-Item -ItemType Directory -Force $out | Out-Null

Push-Location (Join-Path $here 'test')
Run go @('build', "-overlay=$overlayJson", '-trimpath', '-ldflags=-checklinkname=0', '-o', (Join-Path $out 'crypto-test'), '.')
Pop-Location

if ($SkipSyncthing) { return }

# 5. Build Syncthing v2.1.2 (reusing existing clone if available).
$stScratch = "$env:TEMP\claude\C--Software-Coding-Projects-ankikoreaderkindle\9f353075-415c-4f02-8922-133efcd77fe4\scratchpad\hwsha\syncthing"
$st = if (Test-Path $stScratch) { $stScratch } else { Join-Path $here 'syncthing' }
if (-not (Test-Path $st)) {
    Run git @('clone', 'https://github.com/syncthing/syncthing', $st)
}
Push-Location $st
Run git @('-c', 'advice.detachedHead=false', 'checkout', '-q', 'v2.1.2')
Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
$env:CGO_ENABLED = '0'
$buildExe = Join-Path $out 'stbuild.exe'
Run go @('build', '-o', $buildExe, 'build.go')
$env:CGO_ENABLED = '1'
$env:GOARM = '7'
$stOverlay = Join-Path $st 'overlay.json'
Copy-Item -Force $overlayJson $stOverlay
$env:GOFLAGS = "-overlay=overlay.json"
$env:EXTRA_LDFLAGS = '-linkmode=external -extldflags=-static'
$outBin = Join-Path $out 'syncthing-patched'
try {
    Run $buildExe @('-goos', 'linux', '-goarch', 'arm',
        '-tags', 'sqlite_omit_load_extension,sqlite_dbstat,netgo,osusergo',
        '-cc', 'zig cc -target arm-linux-musleabi -mcpu=arm1136j_s',
        '-build-out', $outBin,
        'build', 'syncthing')
} finally {
    Remove-Item $stOverlay -ErrorAction SilentlyContinue
    Remove-Item Env:GOFLAGS, Env:EXTRA_LDFLAGS -ErrorAction SilentlyContinue
    Pop-Location
}
Write-Host "built $outBin"

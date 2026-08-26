$ErrorActionPreference = 'Stop'
$Python = (Get-Command python.exe -ErrorAction Stop).Source
& $Python -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw 'AO Office Pool requires Python 3.12'
}
$Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
& $Python -B (Join-Path $Root 'cmd\ao_office_pool.py') @args
exit $LASTEXITCODE

$errorActionPreference = 'SilentlyContinue'

$1 = '0'
$2 = '0'
$3 = '0'
$4 = '0'
$5 = '0'

$installed = @{
    1 = 'Installed'
    0 = 'Missing'
}

If (Get-HotFix KB4490628 -ErrorAction 'SilentlyContinue') {
    $1 = '1'
}
If (Get-HotFix KB4474419 -ErrorAction 'SilentlyContinue') {
    $2 = '1'
}
If (Get-HotFix KB4516655 -ErrorAction 'SilentlyContinue') {
    $3 = '1'
}
If (Get-HotFix KB4534310 -ErrorAction 'SilentlyContinue') {
    $4 = '1'
}
If (Get-HotFix KB4536952 -ErrorAction 'SilentlyContinue') {
    $5 = '1'
}

Write-Output "KB 4490628 = $($installed[[int]$1])"
Write-Output "KB 4474419 = $($installed[[int]$2])"
Write-Output "KB 4516655 = $($installed[[int]$3])"
Write-Output "KB 4534310 = $($installed[[int]$4])"
Write-Output "KB 4536952 = $($installed[[int]$5])"

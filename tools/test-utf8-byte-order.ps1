$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'utf8-byte-order.ps1')

$privateUse = "x$([char]0xE000)"
$supplementary = "x$([char]::ConvertFromUtf32(0x10000))"
$actual = @(
    Sort-Utf8ByteLexicographic -Values @(
        $supplementary,
        'z',
        $privateUse,
        'a',
        $supplementary
    )
)
$expected = @('a', $privateUse, $supplementary, 'z')
if ($actual.Count -ne $expected.Count) {
    throw "UTF-8 byte sorter returned $($actual.Count) values; expected $($expected.Count)"
}
for ($index = 0; $index -lt $expected.Count; $index++) {
    if ($actual[$index] -cne $expected[$index]) {
        throw "UTF-8 byte sorter mismatch at index ${index}"
    }
}

Write-Host 'UTF-8 byte lexicographic sorter passed non-BMP and deduplication checks'

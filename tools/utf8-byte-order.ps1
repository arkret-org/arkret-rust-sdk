function Sort-Utf8ByteLexicographic {
    param([AllowEmptyCollection()][string[]]$Values)

    if ($null -eq $Values -or $Values.Count -eq 0) {
        return
    }

    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    [string[]]$sorted = @($Values | ForEach-Object {
        if ($null -eq $_) {
            throw 'UTF-8 byte sorting does not accept null values'
        }
        [string]$_
    })

    # Insertion sort keeps the comparison rule explicit and independent of
    # PowerShell culture, .NET UTF-16 ordinal behavior, and host locale.
    for ($index = 1; $index -lt $sorted.Length; $index++) {
        $candidate = $sorted[$index]
        $candidateBytes = $encoding.GetBytes($candidate)
        $cursor = $index - 1
        while ($cursor -ge 0) {
            $currentBytes = $encoding.GetBytes($sorted[$cursor])
            $limit = [Math]::Min($currentBytes.Length, $candidateBytes.Length)
            $comparison = 0
            for ($byteIndex = 0; $byteIndex -lt $limit; $byteIndex++) {
                if ($currentBytes[$byteIndex] -lt $candidateBytes[$byteIndex]) {
                    $comparison = -1
                    break
                }
                if ($currentBytes[$byteIndex] -gt $candidateBytes[$byteIndex]) {
                    $comparison = 1
                    break
                }
            }
            if ($comparison -eq 0) {
                $comparison = $currentBytes.Length.CompareTo($candidateBytes.Length)
            }
            if ($comparison -le 0) {
                break
            }
            $sorted[$cursor + 1] = $sorted[$cursor]
            $cursor--
        }
        $sorted[$cursor + 1] = $candidate
    }

    $deduplicated = [System.Collections.Generic.List[string]]::new()
    foreach ($value in $sorted) {
        if ($deduplicated.Count -eq 0 -or $deduplicated[$deduplicated.Count - 1] -cne $value) {
            [void]$deduplicated.Add($value)
        }
    }
    return $deduplicated.ToArray()
}

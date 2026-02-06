function Get-ProcessList { 
    Write-Output "=== Running Processes ==="
    Get-Process | Format-Table -AutoSize

}

function Get-UserList {
    Write-Output "=== Local User Accounts ==="
    Get-LocalUser | Format-Table -AutoSize
}

function Get-PrefetchFiles {
    Write-Output "=== Prefetch Files ==="
    $prefetch = Get-ChildItem "C:\Windows\Prefetch\*.pf" -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime, Length
    
    if ($prefetch) {
        $prefetch | Format-Table -AutoSize
    } else {
        Write-Output "(No prefetch files found on this system)"
    }
}
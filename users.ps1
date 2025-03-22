Write-Host "`nStarting Windows User Hardening!`n"

function Main {
    Get-LocalUser | ForEach-Object { 
        if ($_ -and $_.Name -notin @('krbtgt', 'DefaultAccount', 'WDAGUtilityAccount')) {
            HardenUser -Username $_.Name 
        }
    }
}

function HardenUser {
    param (
        [string]$username
    )    
    $newadminpass = GenerateStrongPassword
    Write-Host "$username's New Password: $newadminpass"
    net user $username $newadminpass
}

function GenerateStrongPassword {
    $length = 64

    $charSet = @(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789'
    ) -join ''

    -join (1..$length | ForEach-Object { $charSet[(Get-Random -Maximum $charSet.Length)] })
}

Main

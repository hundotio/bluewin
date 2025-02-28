# Title:    Fun Hardening Script!
# Author:   hun

# -------------------------------

# Host and User Information:
$Hosts = @{
    "Wire"   = @{
        IP      = "192.168.18.1"
        Service = @("80", "443", "3389") # IIS
        Users   = @("goon1", "goon2", "hacker")
        Admins  = @("buyer", "lockpick", "safecracker")
    }

    "Office" = @{
        IP      = "10.18.1.2"
        Service = @("443", "3389") # HTTPS
        Users   = @("goon1", "goon2", "hacker")
        Admins  = @("buyer", "lockpick", "safecracker")
    }

    "Teller" = @{
        IP      = "10.18.1.3"
        Service = @("5985", "5986", "3389") # WinRM
        Users   = @("goon1", "goon2", "hacker")
        Admins  = @("buyer", "lockpick", "safecracker")
    }

    "Safe" = @{
        IP      = "10.18.1.12"
        Service = @("23", "3389")  # Telnet
        Users   = @("goon1", "goon2", "hacker")
        Admins  = @("buyer", "lockpick", "safecracker")
    }

    "Vault" = @{
        IP      = "10.18.1.1"
        Service = @("53", "88", "135", "389", "636", "445", "3389") # DNS, KERBEROS, RPC, LDAP, SMB (AD DS)
        Users   = @("getaway", "driver")
        Admins  = @("watchdog", "manager", "mastermind")
    }
    "win" = @{
        IP      = "10.0.1.16"
        Service = @("53", "88", "135", "389", "636", "445", "3389")
        Users   = @("user.one", "user.two")
        Admins   = "mastermind"
    }
}

$Tools = @{
    "Process Explorer" = "https://download.sysinternals.com/files/ProcessExplorer.zip"
    "Process Monitor"  = "https://download.sysinternals.com/files/ProcessMonitor.zip"
    "Autoruns"         = "https://download.sysinternals.com/files/Autoruns.zip"
    "TCPView"          = "https://download.sysinternals.com/files/TCPView.zip"
}

# Pull hostname and verify it's correct
function CheckHostname {
    #$PCName = "vault"
    $PCName = $env:computername

    if ($Hosts.ContainsKey($PCName)){
        Write-Host ("Host appears to be " + $PCName + ". Begin lockdown? (y/n)")
        $input = Read-Host
        if($input -eq "y"){
            if($PCName -ieq "vault"){
                Domain($PCName)
            }
            else{
                Local($PCName)
            }
        }
        elseif($input -eq "n"){
            ChooseHost  # Call ChooseHost if input is 'n'
        }
        else{
            Write-Host "Invalid Input."
        }
    }
}

# Specify host if the hostname does not match
function ChooseHost {
    Write-Host "Hostname not recognized. What system do you want to lock down?"
    $x = 1
    $hostnames = @()  # Create an array to store hostnames
    foreach ($hostname in $Hosts.Keys) {
        Write-Host "$x. $hostname"
        $hostnames += $hostname  # Add the hostname to the array
        $x++
    }

    # Get user input
    $input = Read-Host "Please enter the number of the system you want to lock down"

    # Check if input is valid
    if ($input -ge 1 -and $input -le $hostnames.Count) {
        $selectedHost = $hostnames[$input - 1]  # Correctly map user input to the selected host
        Write-Host ""
        Write-Host "You have selected: $selectedHost"
        Write-Host ""
        LockdownHost $selectedHost  # Call lockdown function for the selected host
    }
    else {
        Write-Host "Invalid input. Please enter a valid number."
    }
}

# Lock down the specified host
function LockdownHost($hostname) {
    $HostData = $Hosts[$hostname]
    Write-Host "Locking down $hostname. (IP: $($HostData.IP), Services: $($HostData.Service -join ', '))"
    if ($hostname -ieq "vault") {
        Domain $hostname  # Call Domain for Vault
    } else {
        Local $hostname  # Call Windows for other hosts
    }
}

# For Active Directory hardening
function Domain($PCName) {
    Local $PCName

    $HostData = $Hosts[$PCName]

    Write-Host "`nStarting Active Directory Hardening!`n"

    Write-Host "`nGetting AD Trust..."
        Get-ADTrust -filter *

    Write-Host "`nStrengthening Password Policy..."
        $VaultDomain = (Get-ADDomain).DNSRoot
        Set-ADDefaultDomainPasswordPolicy -Identity $VaultDomain `
            -LockoutDuration 00:40:00 `
            -LockoutObservationWindow 00:10:00 `
            -ComplexityEnabled $True `
            -ReversibleEncryptionEnabled $False `
            -MaxPasswordAge 10.00:00:00 `
            -MinPasswordLength 30

    Write-Host "`nChecking for Reversible Encryption..."
        Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq "true"} | Select Name, sAMAccountName
    Write-Host "`nChecking DNS Zoning..."
        Get-DnsServerZone | Format-Table -AutoSize

    Write-Host "`nDisabling MAQ for Domain Users..."
        # https://www.jorgebernhardt.com/how-to-change-attribute-ms-ds-machineaccountquota/
        $MAQStatus = (Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
        if ($MAQStatus -gt 0) {
            Set-ADObject -Identity (Get-ADDomain).DistinguishedName -Replace @{"ms-DS-MachineAccountQuota"=0}
        }
        else {
            Write-Host "Machine Account Quota is Disabled!"
        }

    Write-Host "`nQuerying Constrained Delegation..."
        Get-ADUser -Filter * -Properties msDS-AllowedToDelegateTo | Where-Object { $_."msDS-AllowedToDelegateTo" -ne $null -and $_."msDS-AllowedToDelegateTo".Count -gt 0 } | Select-Object SAMAccountName, msDS-AllowedToDelegateTo
        Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo | Where-Object { $_."msDS-AllowedToDelegateTo" -ne $null -and $_."msDS-AllowedToDelegateTo".Count -gt 0 } | Select-Object SAMAccountName, msDS-AllowedToDelegateTo
    Write-Host "`nQuerying User SPNs..."
        Get-ADUser -Filter 'servicePrincipalName -like "*"' -Properties servicePrincipalName | Select-Object SamAccountName, servicePrincipalName

    Write-Host "`nQuerying Unconstrained Delegation..."
        Get-ADUser -Filter * -Properties TrustedForDelegation | Where-Object { $_.TrustedForDelegation -eq $true } | Select-Object SAMAccountName, TrustedForDelegation
        Get-ADComputer -Filter * -Properties TrustedForDelegation | Where-Object { $_.TrustedForDelegation -eq $true } | Select-Object SAMAccountName, TrustedForDelegation

    Write-Host "`nQuerying No Preauthentication Required..."
        Get-ADUser -Filter * -Properties UserAccountControl | Select-Object SAMAccountName, @{Name="DoesNotRequirePreAuth";Expression={($_.UserAccountControl -band 0x40) -eq 0x40}}

    gpupdate /force
    Write-Host "`nDone!`n"
}

# For local windows hardening
function Local($PCName) {
    Write-Host "`nStarting Local Windows Hardening!`n"

    $HostData = $Hosts[$PCName]
    
    Write-Host "`nListing Running Listening Services..."
        netstat -ano | findstr LISTEN
        Get-Service | Where-Object { $_.Status -eq "Running" } | Sort-Object DisplayName
        netsh advfirewall firewall show rule name=all | findstr LocalPort
    
    Write-Host "`nDisabling Other Admin Users..."
        if ($HostData.Admins.Count -eq 1) {
            $EnabledAdmin = $HostData.Admins
            Write-Host "Only one admin found: $EnabledAdmin. Keeping it enabled."
        } elseif ($HostData.Admins.Count -gt 1) {
            # Randomly select one admin to keep enabled
            $EnabledAdmin = Get-Random -InputObject $HostData.Admins

            foreach ($user in $HostData.Admins) {
                if ($user -eq $EnabledAdmin) {
                    Write-Host "Keeping $user enabled."
                } else {
                    Write-Host "Disabling $user."
                    disable-localuser -name $user
                }
            }
        } else {
            Write-Host "No admin users found in HostData.Admins."
        }

    Write-Host "`nChanging Local User Passwords..."
        # Change each user password
        foreach($user in $HostData.Users){
            $newlocalpass = Generate-StrongPassword
            Write-Output "$user's New Password: $newlocalpass"
            net user $user $newlocalpass
        }
    
    Write-Host "`nChanging Local Admin Passwords..."
        # Change each user password
        foreach($user in $HostData.Admins){
            $newadminpass = Generate-StrongPassword
            Write-Output "$user's New Password: $newadminpass"
            net user $user $newadminpass
        }
    
    Write-Host "`nChanging Admin Usernames..."
        foreach($user in $HostData.Admins){
            $newadminusername = Generate-StrongUsername
            Write-Output "$user's New Username: $newadminusername"
            rename-localuser -name "$user" -newname "$newadminusername"
        }
    
    Write-Host "`nDisabling Guest SMB..."
        $GuestSMBStatus = (Get-SMBClientConfiguration).EnableInsecureGuestLogons
        if($GuestSMBStatus -eq "False"){
            Write-Host "Guest SMB is Disabled!"
        }
        else{
            Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RestrictNullSessAccess -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RestrictAnonymous -Value 1
        }
    Write-Host "`nDisabling Default Users..."
        disable-localuser -name "Guest"
        disable-localuser -name "WDAGUtilityAccount"
        disable-localuser -name "DefaultAccount"

    Write-Host "`nDisabling Anonymous RPC..."
        # https://github.com/OrganizedMayhem/PowerShell-Compliance-Scripts/blob/master/Compliance.ps1
        $RestrictAnonymousStatus =  (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous).restrictanonymous
        $RestrictAnonymousSAMStatus = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM).restrictanonymoussam
        
        if($RestrictAnonymousStatus -eq 0){
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -Value 1
        }
        else {
            Write-Host "RestrictAnonymous is Enabled!"
        }

        if($RestrictAnonymousSAMStatus -eq 0){
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM -Value 1
        }
        else {
            Write-Host "RestrictAnonymousSAM is Enabled!"
        }
        
    Write-Host "`nDisabling SMBv1..."
        $SMB1Status = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
        if($SMB1Status -eq "Disabled"){
            Write-Host "SMBv1 is disabled!"
        }
        else{
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        }

    Write-Host "`nDisabling LLMNR..."
        REG ADD "HKLM\Software\policies\Microsoft\Windows NT\DNSClient"
        REG ADD "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f

        $LLMNRStatus = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -name EnableMulticast).EnableMulticast

        if($LLMNRStatus -eq 0){
            Write-Host "LLMNR is disabled!"
        }
        else{
            Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0
            Write-Host "LLMNR has been disabled!"
        }

    Write-Host "`nDisabling IPv6..."
        $interfaces = Get-NetAdapter
        
        foreach ($interface in $interfaces) {
            # Get the IPv6 binding status for each interface
            $IPV6Status = Get-NetAdapterBinding -InterfaceAlias $interface.Name -ComponentID ms_tcpip6

            if ($IPV6Status.Enabled -eq $true) {
                Write-Host "Disabling IPv6 on adapter: $($interface.Name)"
                Disable-NetAdapterBinding -Name $interface.Name -ComponentID ms_tcpip6
            } else {
                Write-Host "IPv6 is already disabled on adapter: $($interface.Name)"
            }
        }

    Write-Host "`nDisabling LM and NTLMv1 Authentication..."
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
    Write-Host "`nEnabling SMB Signing..."
        # Check the current SMB Server and Client Signing status
        $ServerSigningStatus = (Get-SMBServerConfiguration).RequireSecuritySignature
        $ClientSigningStatus = (Get-SmbClientConfiguration).RequireSecuritySignature

        # Enable SMB Signing if not already enabled
        if ($ServerSigningStatus -eq $false -or $ClientSigningStatus -eq $false) {
            Write-Host "Enabling SMB Signing..."

            # Enable SMB server and client signing
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1

            # Restart services to apply changes
            Restart-Service -Name "lanmanserver" -Force  # For SMB server side
            Restart-Service -Name "lanmanworkstation" -Force  # For SMB client side
        } else {
            Write-Host "SMB Signing is already enabled!"
        }

    Write-Host "`nInstalling Monitoring Tools..."
        foreach($tool in $Tools.Keys){
            Write-Host "Installing $tool..."
            $URL = $($Tools[$tool])
            $ZIP = [System.IO.Path]::GetFileName($URL)
            Invoke-WebRequest $URL -OutFile $ZIP
            Expand-Archive -Path $ZIP -DestinationPath ./ -Force
        }
    
    Write-Host "`nMinimzing Firewall to Set Services..."
        # Start RDP Service
        Set-Service -Name TermService -StartupType Automatic
        Start-Service -Name TermService

        if ((Get-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)").Enabled -eq $false) {
            Enable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)"
        }

        # Block all inbound and outbound traffic
        netsh advfirewall reset
        netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

        # # Enable service for the specified host
        foreach($port in $HostData.Service){
            netsh advfirewall firewall add rule name="Allow $port Outbound" dir=out protocol=tcp remoteport=$port localport=$port action=allow
            netsh advfirewall firewall add rule name="Allow $port Inbound" dir=in protocol=tcp remoteport=$port localport=$port action=allow
        }

        # Ensure RDP didn't go down
        Set-Service -Name TermService -StartupType Automatic
        Start-Service -Name TermService
        Enable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)"
    
    Write-Host "`nDone!`n"
}

function Generate-StrongPassword {
    $length = 64

    $charSet = @(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789'
        #'-!"#$%&()*,./:;?@[]^_`{|}~+<=>'    # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
    ) -join ''

    -join (1..$length | ForEach-Object { $charSet[(Get-Random -Maximum $charSet.Length)] })
}

function Generate-StrongUsername {
    $length = 15

    $charSet = @(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789'
    ) -join ''

    -join (1..$length | ForEach-Object { $charSet[(Get-Random -Maximum $charSet.Length)] })
}

function Main {
    Write-Host "Fun Hardening Script!"
    Write-Host "By: Hun!`n"
    CheckHostname  # Call CheckHostname to start the process
}

Main

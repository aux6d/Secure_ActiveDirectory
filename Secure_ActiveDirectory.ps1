Import-Module ActiveDirectory

# Enable Audit Policy for Directory Services Changes
Set-AdmPwdAuditPolicy -AuditDirectoryServiceChangesEnabled $true

# Enable Advanced Audit Policy Configuration
AuditPol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Enforce strong passwords
$PasswordPolicy = Get-AdmPwdPasswordPolicy
$PasswordPolicy.EnforcePasswordHistory = 10
$PasswordPolicy.MaxPasswordAge = 90
$PasswordPolicy.MinPasswordLength = 12
$PasswordPolicy.ComplexityEnabled = $True
Set-AdmPwdPasswordPolicy -Identity $PasswordPolicy

# Enable Account Lockout Policy
$LockoutPolicy = Get-AdmPwdLockoutPolicy
$LockoutPolicy.AccountLockoutDuration = 30
$LockoutPolicy.AccountLockoutThreshold = 10
$LockoutPolicy.ResetLockoutCounterAfter = 30
Set-AdmPwdLockoutPolicy -Identity $LockoutPolicy

# Enable User Account Control (UAC) for all users
$UACvalue = 65536
Get-ADUser -Filter * -Properties UserAccountControl | ForEach-Object {
    $UAC = $_.UserAccountControl
    if ($UAC -band $UACvalue -eq $UACvalue) {
        Write-Output "$($_.Name) already has UAC enabled."
    } else {
        $_.UserAccountControl = $UAC -bor $UACvalue
        Set-ADUser $_
        Write-Output "$($_.Name) UAC has been enabled."
    }
}

# Delegate control of the domain-wide password policy
$Domain = Get-ADDomain
$GroupName = "Password Policy Admins"
$GroupScope = "Global"
$GroupCategory = "Security"
$Group = Get-ADGroup -Filter {Name -eq $GroupName} -ErrorAction SilentlyContinue
if (!$Group) {
    Write-Output "Creating group $GroupName."
    New-ADGroup -Name $GroupName -SamAccountName $GroupName -GroupScope $GroupScope -GroupCategory $GroupCategory
    $Group = Get-ADGroup -Filter {Name -eq $GroupName}
}
$DelegationPrincipal = "Password Policy Admins"
$DelegationRights = "Reset Password","Read and execute","Read","Write all properties"
Write-Output "Delegating control of password policy to $DelegationPrincipal."
$ACL = Get-Acl "AD:\$($Domain.DistinguishedName)"
$Ar = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($DelegationPrincipal,$DelegationRights,"Allow")
$ACL.SetAccessRule($Ar)
Set-Acl "AD:\$($Domain.DistinguishedName)" $ACL
Add-ADPrincipalGroupMembership -Identity $DelegationPrincipal -MemberOf $Group.Name

# Enable protection against Pass-the-Hash attacks
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

# Enable protection against Pass-the-Ticket attacks
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

# Disable LLMNR on the local computer
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "EnableICMPRedirect" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0

# Disable LLMNR on the network adapter
Get-NetAdapter | ForEach-Object {
    Set-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -Enabled $False
    Set-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip -Enabled $False
}

#Disable SMB1 protocol
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
Restart-Service -Name "Server"

#Disable non-admin users from adding up to 10 computers to a domain
$registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$registryValue = "AllowAddWorkstations"

Set-ItemProperty -Path $registryPath -Name $registryValue -Type DWORD -Value 0

# Set the "Network Security: LAN Manager authentication level" policy to "Send NTLMv2 response only\refuse LM & NTLM"
# Note: This policy may also be set using the Local Group Policy Editor (gpedit.msc) or the Domain Group Policy Editor (gpmc.msc)

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 5

# Restart the machine for the changes to take effect

# Set the "Security Options: Interactive Logon: Digest authentication for Windows-based authentication" policy to "Disabled"
# Note: This policy may also be set using the Local Group Policy Editor (gpedit.msc) or the Domain Group Policy Editor (gpmc.msc)

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0

# Restart the machine for the changes to take effect
Restart-Computer

################################################################################################
# De Greyt Jurgen - Dataplan - 06/2022
################################################################################################
Start-Transcript -Path C:\Temp\AdAuditlog.log -Append
# Custom PSArray
$DataExports = New-Object System.Collections.ArrayList
$TasksExport = New-Object System.Collections.ArrayList
# Get privileged groups and its members
$AuditRoot = "C:\temp"
# Checking if Temp folder exists
If ($AuditRoot) {
    Write-Host "Temp Folder is present" -ForegroundColor Green
}
Else {
    Write-Warning "Temp folder not retrieved, creating Temp Folder"
    New-Item -Name Temp -Path "C:\" -ItemType Directory
}
$FNDate = (Get-date -format dd-M-yyy)
$FN = "$FNDate"+"ADAudit" 
$AuditDir = "$AuditRoot\$FN"
If (!(Test-Path -Path $AuditDir)) {
    Write-warning "Audit folder missing, creating Auditfolder under $($Auditroot)"
    New-Item -Name $FN -ItemType Directory -Path $AuditRoot
}
Else {
    Write-Host "Audit directory already present" -ForegroundColor Green
}
$Domains = (Get-adforest).Domains
Foreach ($dom in $Domains) {
    $DomSN = ($dom -split "[.]")[0]
    # Getting AdminSDHolder protected groups
    $Groups = Get-adgroup -filter {AdminCount -eq "1"} -Server $dom
    Foreach ($Obj in $Groups) {
        Get-adgroup -filter {Name -eq $Obj.Name} -server $Dom | get-adgroupmember | select-Object Name, DistinguishedName |  export-csv -path $AuditDir\$($Obj.name)-$($DomSN).csv -delimiter ";" 
    }
    # Get Default Password policy
    $PWGPO = Get-ADDefaultDomainPasswordPolicy
    $PWTTL = ($PWGPO.MaxPasswordAge -split "[.]")[0]
    if ($PWGPO.PasswordComplexity -eq $true) {
        Write-Host "Password complexitry is required." -ForegroundColor Green
    }
    Else {
        Write-Warning "Password complexity is not enabled for domain $dom!"
    }
    $fileName = ($dom -split "[.]")[0]
    $PWGPO | Out-file $AuditDir\$($FileName)_PWPolicy.txt
    # Stale accounts
    $StaleUsers = Get-aduser -filter * -properties LastLogonDate, PasswordLastSet, PasswordNeverExpires, whencreated -server $dom | Where-Object {$_.LastLogonDate -le (Get-Date).AddDays(-180)}
    $StaleUsersCount = ($StaleUsers | measure).Count
    If (!($StaleUsers)) {
        Write-Host "No accounts were retrieved which have not logged on the last 180 days." -ForegroundColor Green
        $STaleUsers = "None"
    }
    Else {
        write-Host "The script retrieved $($StaleUsersCount) users which did not log on in the last 180 days" -ForegroundColor Green
        $StaleDisabled = $StaleUsers | Where-Object {$_.Enabled -eq $false}
        $StaleDisabledCount = ($StaleDisabled | Measure).Count
        Write-host "$($StaleDisabledCount) of these users are already disabled" -ForegroundColor Green
        $StaleEnabled = $StaleUsersCount - $StaleDisabledCount
        If ($StaleEnabled -eq "0") {
            Write-Host "No users have been retrived which have not logged on in the last 180 days, and are still enabled." -ForegroundColor Green
        }
        Else {
            Write-host "The script has retrieved $($StaleEnabled) users which have not loged on in the last 180 days, but have not been disabled" -ForegroundColor Green
            $StaleEnabledUsers = $StaleUsers | Where-Object {$_.Enabled -eq $true}
            Write-Host "Exporting Stale users to csv" -ForegroundColor Green
            $StaleEnabledUsers | Select Name, DistinguishedName, LastlogonDate, whencreated | Export-csv -Path $AuditDir\StaleUsers_$($fileName)-$($DomSN).csv -Delimiter ";"
        }
    }
    # User Accounts which passwords have not been updated
    $ExpiredPWUSers = Get-aduser -filter * -Properties PasswordLastSet, PasswordNeverExpires, WhenCreated, LastLogonDate -server $dom | Where-Object {$_.PasswordLastSet -le (Get-Date).AddDays(-$($PWTTL))}
    $ExpiredPWUSersCount = ($ExpiredPWUSers | Measure).Count
    $EnabledExpiredPW = $ExpiredPWUSers | Where-Object ($_.Enabled -eq $true)
    $EnabledExpiredPWCount = ($EnabledExpiredPW | Measure).count
    $PWNeverExpires = $EnabledExpiredPW | Where-Object {$_.PasswordNeverExpires -eq $true}
    $PWNeverExpiresCount = ($PWNeverExpires | measure).count
    Write-Host "The script has retrieved $($ExpiredPWUSersCoun) users from $($dom)" -ForegroundColor Green
    Write-Host "$($EnabledExpiredPWCount) of these users are still enabled, and failed to change their passwords in the last $($PWTTL) days" -ForegroundColor Green
    Write-Host "The enabled users who failed to change theirs passwords have been exported to $($auditDir)\PWNeverChanged.csv"
    # Exporting Data to csv
    $EnabledExpiredPW | Select-Object Name, DistinguishedName, PasswordLastSet, PasswordNeverExpires, Enabled | Export-csv -Path $auditDir\PWNeverChanged-$($DomSN).csv -Delimiter ";"
    # Computer Report
    # We want to know which computer operating systems are still listed in the domain
    $Computers = Get-AdComputer -filter * -Server $Dom -Properties OperatingSystem, whencreated, LastLogonDate
    $Computerscount = ($Computers | Measure).Count
    Write-Host "Retrieved $($Computerscount) computers from the domain $($DomSN)" -ForegroundColor Green
    $EnabledComputers = $Computers | Where-Object {$_.Enabled -eq $true}
    $EnabledComputersCount = ($EnabledComputers | Measure).count
    $DisabledComputersCount = $Computerscount - $EnabledComputersCount
    Write-Host "$($EnabledComputersCount) Computers are enabled, wherefore $($DisabledComputersCount) are disabled" -ForegroundColor Green
    # Operating Systems in use
    $OSs = $EnabledComputers | Sort-Object OperatingSystem -Unique | Select-Object OperatingSystem
    Write-Host "Following Operating Systems where retreived from the domain" -ForegroundColor Green
    foreach ($OS in $OSs) {
        Write-Host "$($OS)" -ForegroundColor Yellow
    }
    $StaleComputers = $EnabledComputers | Where-Object {$_.PasswordLastSet -le (Get-Date).AddDays(-30)}
    $StaleComputersCount = ($StaleComputers | Measure).count
    Write-Host "$($StaleComputersCount) computers failed to update their password the last 30 days, wherefore they might be inactive, these computers are exported to $($AuditDir)\StaleComputers-but-enabled-$($domsn).csv" -ForegroundColor Green
    $StaleComputers | Select-Object * | Export-csv -Path "$($AuditDir)\StaleComputers-but-enabled-$($domsn).csv" -Delimiter ";"
    # Service Accounts on Servers
    Write-Host "Getting Service Accounts on the server operating systems" -ForegroundColor Green
    $Servers = $EnabledComputers | Where-Object {$_.OperatingSystem -like "*Server*"}
    foreach ($Server in $Servers) {
        Write-Host "Testing Connection to $($Server.DNSHostName)" -ForegroundColor Green
        If (Test-Connection $Server.dnsHostname -Count 2 -ErrorAction SilentlyContinue) {
            Write-Host "Could successfully ping $($Server.DNSHostName)" -ForegroundColor Green
            Write-Host "Getting Service Accounts On server $($Server.DNSHostName)" -ForegroundColor Green
            <#If ($Server.DistinguishedName -like "*Domain Controllers*") {
                Write-Host "Checking Domain Controller $($Server.HostName)"
                $Services = Get-WMIObject Win32_Service -ComputerName $Server.HostName | Where-Object {($_.StartName -ne $null) -and ($_.StartName -ne "LocalSystem") -and ($_.StartName -notlike "NT AUTHORITY*")} | select Name, STartName, StartMode       
                $ServerName = $Server.hostName
            }
            Else {
                Write-Host "Checking Server $($Server.DNSHostName)"
                $Services = Get-WMIObject Win32_Service -ComputerName $Server.DNSHostName | Where-Object {($_.StartName -ne $null) -and ($_.StartName -ne "LocalSystem") -and ($_.StartName -notlike "NT AUTHORITY*")} | select Name, STartName, StartMode       
                $ServerName = $Server.DnsHostName
            }#>
            Write-Host "Checking Server $($Server.DNSHostName)"
            $Services = Get-WMIObject Win32_Service -ComputerName $Server.DNSHostName | Where-Object {($_.StartName -ne $null) -and ($_.StartName -ne "LocalSystem") -and ($_.StartName -notlike "NT AUTHORITY*") -and ($_.StartName -notLike "NT Service*")} | select-Object Name, STartName, StartMode       
            $ServerName = $Server.DnsHostName
            If ($Services) {
                Write-Host "Server $($ServerName) contains services which are handled by a custom service account." -ForegroundColor Green
                Foreach ($Service in $Services) {
                    $DataExport = New-Object -TypeName psobject
                    $DataExport | Add-Member -Name "ServerName" -MemberType NoteProperty -Value $ServerName
                    $DataExport | Add-Member -Name "ServiceName" -MemberType NoteProperty -Value $Service.Name
                    $DataExport | Add-Member -Name "ServiceAccount" -MemberType NoteProperty -Value $Service.StartName
                    $DataExport | Add-Member -Name "Startmode" -MemberType NoteProperty -Value $Service.StartMode
                    $DataExports.add($DataExport) | Out-Null
                }
            }
            Else {
                Write-Host "Server $($ServerName) does not contain any services which are started by a service account" -ForegroundColor Yellow
            }
            $DataExports | Select * | Export-Csv -Path $AuditDir\ServiceAccounts-$($domsn).csv
            # Get ScheduledTasks
            $CustomTasks = Get-ScheduledTask -CimSession $Server.dnsHostname | ? {($_.Principal.userID -ne "System") -and ($_.Principal.userID -ne "Network Service") -and ($_.Principal.userID -ne "Local Service") -and ($null -ne $_.Principal.userid)}
            If ($CustomTasks) {
                Write-Host "Custom Tasks found on $($Server.DNSHostName)" -ForegroundColor Yellow
                foreach ($Task in $CustomTasks) {
                    $TaskExport = New-Object -TypeName psobject
                    $TaskExport | Add-Member -Name TaskName -MemberType NoteProperty -Value $Task.TaskName
                    $TaskExport | Add-Member -Name Description -MemberType NoteProperty -Value $Task.Description
                    $TaskExport | Add-Member -Name UserID -MemberType NoteProperty -Value $Task.Principal.userID
                    $TaskExport | Add-Member -Name Host -MemberType NoteProperty -Value $Server.DnsHostName
                    $TasksExport.add($TaskExport) | Out-Null
                }
            }
            $TasksExport | Select * | Export-csv -Path $AuditDir\SCheduledTasks-$($domsn).csv
        }
        Else {
            Write-Warning "The computer $($Server.dnsHostname) could not be pinged"
        }
    }
}
Stop-Transcript
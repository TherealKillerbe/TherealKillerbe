$DataExports = New-Object System.Collections.ArrayList
$Servers = Get-AdComputer -Filter {OperatingSystem -like "*Server*"} -Properties * 
Foreach ($Server in $Servers) {
    # Getting Services on Local Server
    If ($Server.DistinguishedName -like "*Domain Controllers*") {
        Write-Host "Checking Domain Controller $($Server.HostName)"
        $Services = Get-WMIObject Win32_Service -ComputerName $Server.HostName | Where-Object {($_.StartName -ne $null) -and ($_.StartName -ne "LocalSystem") -and ($_.StartName -notlike "NT AUTHORITY*")} | select Name, STartName, StartMode       
        $ServerName = $Server.hostName
    }
    Else {
        Write-Host "Checking Server $($Server.DNSHostName)"
        $Services = Get-WMIObject Win32_Service -ComputerName $Server.DNSHostName | Where-Object {($_.StartName -ne $null) -and ($_.StartName -ne "LocalSystem") -and ($_.StartName -notlike "NT AUTHORITY*")} | select Name, STartName, StartMode       
        $ServerName = $Server.DnsHostName
    }
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
}
$DataExports | Select * | Export-Csv -Path C:\Temp\ServiceAccounts.csv
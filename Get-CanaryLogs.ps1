<#
.SYNOPSIS
    Get-CanaryLogs.ps1 is a PowerShell script for retrieving Canary incident and audit events from the Canary API and sending the logs as webhooks to a listener.
.DESCRIPTION
    Get-CanaryLogs.ps1 is a PowerShell script for retrieving Canary incident and audit events from the Canary API and sending the logs as webhooks to a listener.
    Global configuration parameters are stored as JSON in Get-CanaryLogs_config.json (or whatever you want to name it, see line 21 below).
.PARAMETER IgnoreCertErrors
    (Switch) Will ignore certificate errors.  Useful in environments with proxies or other HTTPS intermediaries.
.EXAMPLE
    Get-CanaryLogs.ps1 -IgnoreCertErrors
.NOTES
    Tested with Canary API v1 (as of June 30, 2021)    
    Change Log:
        2021/06/11 - First draft version
        2021/06/16 - Added functionality to fetch audit events
        2021/06/30 - Added UNIX datetime fields
 #>

[CmdletBinding()]
param(
    [switch]$IgnoreCertErrors
)

### Global Variables - yeah I know they're bad, don't @ me ###

$configfile = "C:\LogRhythm\Scripts\Get-CanaryLogs\Get-CanaryLogs_config.json"
$config = Get-Content -Raw $configfile | ConvertFrom-Json
$logfile = $config.logfile
$globalloglevel = $config.loglevel
$statefile = $config.statefile
$domainhash = $config.domainhash
$apitoken = $config.apitoken
$auditfetchlimit = $config.auditfetchlimit
$webhookendpoint = $config.webhookendpoint
$auditfetcherror = ""
$incidentfetcherror = ""

### Goofy certificate stuff ###

if ($IgnoreCertErrors.IsPresent) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()
}
Else {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

 Function Write-Log {  

    # This function provides logging functionality.  It writes to a log file provided by the $logfile variable, prepending the date and hostname to each line
    # Currently implemented 4 logging levels.  1 = DEBUG / VERBOSE, 2 = INFO, 3 = ERROR / WARNING, 4 = CRITICAL
    # Must use the variable $globalloglevel to define what logs will be written.  1 = All logs, 2 = Info and above, 3 = Warning and above, 4 = Only critical.  If no $globalloglevel is defined, defaults to 2
    # Must use the variable $logfile to define the filename (full path or relative path) of the log file to be written to
               
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)] [string]$logdetail,
        [Parameter(Mandatory = $false)] [int32]$loglevel = 2
    )
    if (($globalloglevel -ne 1) -and ($globalloglevel -ne 2) -and ($globalloglevel -ne 3) -and ($globalloglevel -ne 4)) {
        $globalloglevel = 2
    }

    if ($loglevel -ge $globalloglevel) {
        try {
            $logfile_exists = Test-Path -Path $logfile
            if ($logfile_exists -eq 1) {
                if ((Get-Item $logfile).length/1MB -ge 10) {
                    $logfilename = [io.path]::GetFileNameWithoutExtension($logfile)
                    $newfilename = "$($logfilename)"+ (Get-Date -Format "yyyyMMddhhmmss").ToString() + ".log"
                    Rename-Item -Path $logfile -NewName $newfilename
                    New-Item $logfile -ItemType File
                    $this_Date = Get-Date -Format "MM\/dd\/yyyy hh:mm:ss tt"
                    Add-Content -Path $logfile -Value "$this_Date [$env:COMPUTERNAME] $logdetail"
                }
                else {
                    $this_Date = Get-Date -Format "MM\/dd\/yyyy hh:mm:ss tt"
                    Add-Content -Path $logfile -Value "$this_Date [$env:COMPUTERNAME] $logdetail"
                }
            }
            else {
                New-Item $logfile -ItemType File
                $this_Date = Get-Date -Format "MM\/dd\/yyyy hh:mm:ss tt"
                Add-Content -Path $logfile -Value "$this_Date [$env:COMPUTERNAME] $logdetail"
            }
        }
        catch {
            Write-Error "***ERROR*** An error occured writing to the log file: $_"
        }
    }
}

### Sweet Functions ###

Function Get-State {
    $statefile_exists = Test-Path -Path $statefile
    if ($statefile_exists -eq $false) {
        Write-Log -loglevel 2 -logdetail "State file does not exist. Script will proceed with last updated_id = 0"
        $incident_state = 0
        $audit_state = 0
    }
    Else{
        Try {
            Write-Log -loglevel 1 -logdetail "Reading state from state file $($statefile)"
            $state = Get-Content $statefile | ConvertFrom-Json
            [Int32]$incident_state = $state.incidentstate
            [Int32]$audit_state = $state.auditstate
            Write-Log -loglevel 1 -logdetail "Retrieved incident state: $($incident_state); and audit state: $($audit_state) from $($statefile)"        
        }
        Catch {
            Write-Log -loglevel 3 -loglevel "***WARNING*** Could not read $($statefile). Script will proceed with last updated_id = 0"
                    $incident_state = 0
                    $audit_state = 0  
        }
    }
    $statearray = New-Object PSObject -Property @{
        "incidentstate" = $incident_state
        "auditstate" = $audit_state
    }
    Return $statearray
}

Function Write-State {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]$IncidentState,
        [int]$AuditState
    )
    $stateJson = New-Object PSObject -Property @{
        "incidentstate" = $IncidentState
        "auditstate" = $AuditState
    }
    
    try {
        $state_exists = Test-Path -Path $statefile
        if ($state_exists -eq $true) {
            Write-Log -loglevel 1 -logdetail "Writing last update ids (Audit: $($stateJson.auditstate); Incident: $($stateJson.incidentstate)) to state file $($statefile)"
            $stateJson | ConvertTo-Json | Out-File -FilePath $statefile
        }
        else {
            Write-Log -loglevel 1 -logdetail "State file does not exist. Creating $($statefile)"
            Write-Log -loglevel 1 -logdetail "Writing last update ids (Audit: $($stateJson.auditstate); Incident: $($stateJson.incidentstate)) to state file $($statefile)"
            $stateJson | ConvertTo-Json | Out-File -FilePath $statefile
        }
    }
    catch {
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured writing to the state file: $_"
    }

}

Function Get-IncidentEvents {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]$LastUpdateID
    )
    $uri = "https://$($domainhash).canary.tools//api/v1/incidents/all?incidents_since=$($LastUpdateID)"
    $params = @{
        'auth_token' = $apitoken
    }
    Write-Log -loglevel 1 -logdetail "Querying API for new incident events..."
    Try {
        $result = Invoke-RestMethod -Uri $uri -Body $params -Method GET
    }
    Catch {
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured retreiving events from API: $_"
        $incidentfetcherror = $_
    }
    $max_update_id = $LastUpdateID
    $total_incidents = 0    
    ForEach ($i in $result.incidents) {
        $total_incidents += 1
        if ($i.updated_id -gt $max_update_id) {
            $max_update_id = $i.updated_id  
        }
    }
    Write-Log -loglevel 2 -logdetail "Retrieved $($total_incidents) total incidents. Last update_id = $($max_update_id)"
    $returnresult = New-Object PSObject -Property @{
        "results" = $result
        "last_id" = $max_update_id
    }
    Return $returnresult 
}

Function Get-AuditEvents {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]$LastUpdateID
    )
    $uri = "https://$($domainhash).canary.tools//api/v1/audit_trail/fetch?limit=$auditfetchlimit"
    $params = @{
        'auth_token' = $apitoken
    }
    Write-Log -loglevel 1 -logdetail "Querying API for new audit events..."
    Try {
        $result = Invoke-RestMethod -Uri $uri -Body $params -Method GET
    }
    Catch {
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured retreiving audit events from API: $_"
        $auditfetcherror = $_
    }
    $max_update_id = $LastUpdateID
    $total_events = 0    
    $audit_trail = @()
    ForEach ($i in $result.audit_trail) {
            if ($i.id -gt $LastUpdateID) {
                if ($i.id -gt $max_update_id) {
                    $max_update_id = $i.id  
                }
            $total_events += 1
            $audit_trail += $i
        }
    }
    Write-Log -loglevel 2 -logdetail "Retrieved $($total_events) total audit events. Last update_id = $($max_update_id)"
    $returnresult = New-Object PSObject -Property @{
        "results" = $audit_trail
        "last_id" = $max_update_id
    }
    Return $returnresult 
}

Function Send-IncidentEvents ($incidents) {
    Write-Log -loglevel 2 -logdetail "Sending incident event results to $($webhookendpoint)..."
    Try {
        if ($incidents.incidents.Count -eq 0) {
            $rawbody = New-Object PSObject -Property @{
                Log_Type = "Canary_ScriptInfo"
                Message = "No new incidents"
                Msg_Time = [int](Get-Date -Date (Get-Date).ToUniversalTime() -UFormat %s -Millisecond 0)
            }
            if ($incidentfetcherror -ne "")  {
                $rawbody.Message = "No incidents sent. There were errors encountered fetching incidents; see log for more details: $($incidentfetcherror)"
            }
            $body = $rawbody | ConvertTo-Json
            $result = Invoke-WebRequest -Uri $webhookendpoint -Body $body -Method POST -UseBasicParsing
            Write-Log -loglevel 2 -logdetail "No new incidents to send.  Sent status message. Result: $($result.StatusCode) $($result.StatusDescription)"
        }
        else {
            Write-Log -loglevel 2 -logdetail "Sending $(($incidents.incidents).Count) incident logs..."
            $counter = 0
            ForEach ($i in $incidents.incidents) {
                $counter++
                $i | Add-Member -NotePropertyName "Log_Type" -NotePropertyValue "Canary_Incident"
                $rawincident = $i | ConvertTo-Json
                $result = Invoke-WebRequest -Uri $webhookendpoint -Body $rawincident -Method POST -UseBasicParsing
                Write-Log -loglevel 2 -logdetail "Incident ($counter) sent. Result: $($result.StatusCode) $($result.StatusDescription)"
            }
        }
    }
    Catch {
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured sending webhook: $_"
    }
}

Function Send-AuditEvents ($audits) {
    Write-Log -loglevel 2 -logdetail "Sending audit event results to $($webhookendpoint)..."
    Try {
        if ($audits.Count -eq 0) {
            $rawbody = New-Object PSObject -Property @{
                Log_Type = "Canary_ScriptInfo"
                Message = "No new audit events"
                Msg_Time = [int](Get-Date -Date (Get-Date).ToUniversalTime() -UFormat %s -Millisecond 0)
            }
            if ($auditfetcherror -ne "")  {
                $rawbody.Message = "No audit events sent. There were errors encountered fetching audit events; see log for more details: $($auditfetcherror)"
            }
            $body = $rawbody | ConvertTo-Json
            $result = Invoke-WebRequest -Uri $webhookendpoint -Body $body -Method POST -UseBasicParsing
            Write-Log -loglevel 2 -logdetail "No new audit events to send.  Sent status message. Result: $($result.StatusCode) $($result.StatusDescription)"
        }
        else {
            Write-Log -loglevel 2 -logdetail "Sending $(($audits).Count) audit events..."
            $counter = 0
            ForEach ($i in $audits) {
                $counter++
                $i | Add-Member -NotePropertyName "Log_Type" -NotePropertyValue "Canary_Audit"
                $normalmsgdate = Get-Date -Date ([datetime]::parseexact($i.timestamp, "yyyy-MM-dd HH:mm:ss UTCzz00", $null)).ToUniversalTime() -UFormat %s    
                $i | Add-Member -NotePropertyName "Msg_Time" -NotePropertyValue $normalmsgdate
                $rawaudits = $i | ConvertTo-Json
                $result = Invoke-WebRequest -Uri $webhookendpoint -Body $rawaudits -Method POST -UseBasicParsing
                Write-Log -loglevel 2 -logdetail "Audit event ($counter) sent. Result: $($result.StatusCode) $($result.StatusDescription)"
            }
        }
    }
    Catch {
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured sending webhook: $_"
    }
}

### MAIN ###

if ($IgnoreCertErrors.IsPresent) {
    Write-Log -loglevel 3 -logdetail "***WARNING*** Script invoked with IgnoreCertErrors. Certificate errors will be ignored"
}
$last_state = Get-State
$incidentresults = Get-IncidentEvents -LastUpdateID $last_state.incidentstate
$auditresults = Get-AuditEvents -LastUpdateID $last_state.auditstate
Send-IncidentEvents $incidentresults.results
Send-AuditEvents $auditresults.results
Write-State -IncidentState $incidentresults.last_id -AuditState $auditresults.last_id
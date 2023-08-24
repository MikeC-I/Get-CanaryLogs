<#
.SYNOPSIS
    Get-CanaryLogs.ps1 is a PowerShell script for retrieving Canary incident and audit events from the Canary API and writing them to local files.
.DESCRIPTION
    Get-CanaryLogs.ps1 is a PowerShell script for retrieving Canary incident and audit events from the Canary API and writing them to local files.
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
        2023/06/30 - Updated for local file functionality
 #>

[CmdletBinding()]
param(
    [switch]$IgnoreCertErrors
)

### Global Variables - yeah I know they're bad, don't @ me ###

$configfile = "C:\LogRhythm\LogScripts\Get-CanaryLogs\Get-CanaryLogs_config_localfile.json"
$config = Get-Content -Raw $configfile | ConvertFrom-Json
$logfile = $config.logfile
$incident_logfile = $config.incidentlogfile
$audit_logfile = $config.auditlogfile
$globalloglevel = $config.loglevel
$statefile = $config.statefile
$domainhash = $config.domainhash
$apitoken = $config.apitoken
$auditfetchlimit = $config.auditfetchlimit
$webhookendpoint = $config.webhookendpoint
$proxy = $config.proxy
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

Function Write-IncidentLog {
    [CmdletBinding()]
    Param([Parameter(Mandatory = $true)] [string]$body)
    $old_logfile = $logfile
    $logfile = $incident_logfile
    Write-Log -loglevel 4 -logdetail $body
    $logfile = $old_logfile
}

Function Write-AuditLog {
    [CmdletBinding()]
    Param([Parameter(Mandatory = $true)] [string]$body)
    $old_logfile = $logfile
    $logfile = $audit_logfile
    Write-Log -loglevel 4 -logdetail $body
    $logfile = $old_logfile
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
        if (($proxy -ne $null) -and ($proxy -ne "")) {

            $result = Invoke-RestMethod -Uri $uri -Body $params -Method GET -UseBasicParsing -Proxy $proxy
        }
        else {
            $result = Invoke-RestMethod -Uri $uri -Body $params -Method GET -UseBasicParsing
        }
    }
    Catch {
        $error = $_.ToString()
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured retreiving events from API: $error"
        $incidentfetcherror = $error
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
        "errors" = $incidentfetcherror
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
        if (($proxy -ne $null) -and ($proxy -ne "")) {
            $result = Invoke-RestMethod -Uri $uri -Body $params -Method GET -UseBasicParsing -Proxy $proxy
        }
        else {
            $result = Invoke-RestMethod -Uri $uri -Body $params -Method GET -UseBasicParsing
        }
    }
    Catch {
        $error = $_.ToString()
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured retreiving audit events from API: $error"
        $auditfetcherror = $error
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
        "errors" = $auditfetcherror
    }    
    Return $returnresult 
}



Function Write-AuditEvents ($audits) {
    Write-Log -loglevel 2 -logdetail "Writing audit event results to $($audit_logfile)..."
    # Write-Log -loglevel 1 -logdetail "[DEBUG] Audit Fetch Error: $auditfetcherror"
    Try {
        if ($audits.results.Count -eq 0) {
            if ($audits.errors -ne "")  {
                $body = "object=|objectname=|objecttype=|hash=|policy=|result=|url=|useragent=|responsecode=|subject=|version=|command=API FETCH ERROR|reason=reason=No audit events written. There were errors encountered fetching audit events; see log for more details: $($auditfetcherror)|action=|status=|sessiontype=|process=|processid=|parentprocessid=|parentprocessname=|parentprocesspath=|quantity=|amount=|size=|rate=|minutes=|seconds=|milliseconds=|session=|kilobytesin=|kilobytesout=|kilobytes=|packetsin=|packetsout=|severity=|vmid=|vendorinfo=|threatname=|threatid=|cve=|smac=|dmac=|sinterface=|dinterface=|sip=|dip=|snatip=|dnatip=|sname=|dname=|serialnumber=|login=|account=|sender=|recipient=|group=|domainimpacted=|domainorigin=|protnum=|protname=|sport=|dport=|snatport=|dnatport=|augmented=|tag1=Canary_Script_Info|tag2=|tag3=|tag4=|tag5=|tag6=|tag7=|tag8=|tag9=|tag10=|"
                Write-Log -loglevel 2 -logdetail "No new audit events written - an error occured querying the API: $auditfetcherror"
            }
            else {
                $body = "object=|objectname=|objecttype=|hash=|policy=|result=|url=|useragent=|responsecode=|subject=|version=|command=|reason=reason=No audit events written. No new audit events found|action=|status=|sessiontype=|process=|processid=|parentprocessid=|parentprocessname=|parentprocesspath=|quantity=|amount=|size=|rate=|minutes=|seconds=|milliseconds=|session=|kilobytesin=|kilobytesout=|kilobytes=|packetsin=|packetsout=|severity=|vmid=|vendorinfo=|threatname=|threatid=|cve=|smac=|dmac=|sinterface=|dinterface=|sip=|dip=|snatip=|dnatip=|sname=|dname=|serialnumber=|login=|account=|sender=|recipient=|group=|domainimpacted=|domainorigin=|protnum=|protname=|sport=|dport=|snatport=|dnatport=|augmented=|tag1=Canary_Script_Info|tag2=|tag3=|tag4=|tag5=|tag6=|tag7=|tag8=|tag9=|tag10=|"
                Write-Log -loglevel 2 -logdetail "No new audit events written - no new events found."
            }
            Write-AuditLog -body $body            
        }
        else {
            Write-Log -loglevel 2 -logdetail "Writing $(($audits.results).Count) audit events..."
            $counter = 0
            ForEach ($i in $audits.results) {
                $counter++
                $i | Add-Member -NotePropertyName "Log_Type" -NotePropertyValue "Canary_Audit"
                $normalmsgdate = Get-Date -Date ([datetime]::parseexact($i.timestamp, "yyyy-MM-dd HH:mm:ss UTCzz00", $null)).ToUniversalTime() -UFormat %s    
                $i | Add-Member -NotePropertyName "Msg_Time" -NotePropertyValue $normalmsgdate
                Try {
                    $logbody = "object=$($i.flock_id)|objectname=$($i.flock_name)|objecttype=|hash=|policy=|result=|url=|useragent=$($i.user_browser_agent)|responsecode=|subject=$($i.additional_information)|version=$($i.version)|command=|reason=$($i.message)|action=$($i.action_type)|status=|sessiontype=|process=|processid=|parentprocessid=|parentprocessname=|parentprocesspath=|quantity=|amount=|size=|rate=|minutes=|seconds=|milliseconds=|session=|kilobytesin=|kilobytesout=|kilobytes=|packetsin=|packetsout=|severity=|vmid=|vendorinfo=|threatname=|threatid=|cve=|smac=|dmac=|sinterface=|dinterface=|sip=$($i.user_ip)|dip=|snatip=|dnatip=|sname=|dname=|serialnumber=$($i.id)|login=$($i.user)|account=|sender=$($i.Log_Type)|recipient=|group=|domainimpacted=|domainorigin=|protnum=|protname=|sport=|dport=|snatport=|dnatport=|augmented=|tag1=$($i.Log_Type)|tag2=$($i.action_type)|tag3=|tag4=|tag5=|tag6=|tag7=|tag8=|tag9=|tag10=|"
                    Write-AuditLog -body $logbody
                    Write-Log -loglevel 1 -logdetail "Audit event $($counter) written: $($logbody)"
                }
                Catch {
                    Write-Log -loglevel 3 -logdetail "***WARNING*** Could not format log body to output: $_"
                }
                
            }
        }
    }
    Catch {
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured writing audit events: $_"
    }
}

Function Write-IncidentEvents ($incidents) {
    Write-Log -loglevel 2 -logdetail "Writing incident event results to $($incident_logfile)"
    Write-Log -loglevel 1 -logdetail "[DEBUG] Incident Fetch Error: $incidentfetcherror"
    Try {
        if ($incidents.results.incidents.Count -eq 0) {
            if ($incidents.errors -ne "")  {
                $body = "object=|objectname=|objecttype=|hash=|policy=|result=|url=|useragent=|responsecode=|subject=|version=|command=API FETCH ERROR|reason=No incidents written. There were errors encountered fetching incidents; see log for more details: $($incidentfetcherror)|action=|status=|sessiontype=|process=|processid=|parentprocessid=|parentprocessname=|parentprocesspath=|quantity=|amount=|size=|rate=|minutes=|seconds=|milliseconds=|session=|kilobytesin=|kilobytesout=|kilobytes=|packetsin=|packetsout=|severity=|vmid=|vendorinfo=|threatname=|threatid=|cve=|smac=|dmac=|sinterface=|dinterface=|sip=|dip=|snatip=|dnatip=|sname=|dname=|serialnumber=|login=|account=|sender=|recipient=|group=|domainimpacted=|domainorigin=|protnum=|protname=|sport=|dport=|snatport=|dnatport=|augmented=|tag1=Canary_Script_Info|tag2=|tag3=|tag4=|tag5=|tag6=|tag7=|tag8=|tag9=|tag10=|"
            }
            else {
                $body = "object=|objectname=|objecttype=|hash=|policy=|result=|url=|useragent=|responsecode=|subject=|version=|command=|reason=No incidents written. No new incident records found|action=|status=|sessiontype=|process=|processid=|parentprocessid=|parentprocessname=|parentprocesspath=|quantity=|amount=|size=|rate=|minutes=|seconds=|milliseconds=|session=|kilobytesin=|kilobytesout=|kilobytes=|packetsin=|packetsout=|severity=|vmid=|vendorinfo=|threatname=|threatid=|cve=|smac=|dmac=|sinterface=|dinterface=|sip=|dip=|snatip=|dnatip=|sname=|dname=|serialnumber=|login=|account=|sender=|recipient=|group=|domainimpacted=|domainorigin=|protnum=|protname=|sport=|dport=|snatport=|dnatport=|augmented=|tag1=Canary_Script_Info|tag2=|tag3=|tag4=|tag5=|tag6=|tag7=|tag8=|tag9=|tag10=|"
            }
            Write-IncidentLog -body $body            
            Write-Log -loglevel 2 -logdetail "No new incidents events written."
        }
        else {
            Write-Log -loglevel 2 -logdetail "Sending $(($incidents.results.incidents).Count) incident logs..."
            $counter = 0
            ForEach ($i in $incidents.results.incidents) {
                $counter++
                $i | Add-Member -NotePropertyName "Log_Type" -NotePropertyValue "Canary_Incident" 
                Try {
                    $logbody = "object=$($i.description.flock_id)|objectname=$($i.description.flock_name)|objecttype=|hash=$($i.hash_id)|policy=|result=|url=|useragent=|responsecode=|subject=|version=|command=$($($i.description.events) -replace "`n",", " -replace "`r",", ")|reason=|action=|status=$($i.description.acknowledged)|sessiontype=|process=|processid=|parentprocessid=|parentprocessname=|parentprocesspath=|quantity=$($i.description.events_count)|amount=|size=|rate=|minutes=|seconds=|milliseconds=|session=|kilobytesin=|kilobytesout=|kilobytes=|packetsin=|packetsout=|severity=|vmid=$($i.description.logtype)|vendorinfo=$($i.description.description)|threatname=|threatid=|cve=|smac=$($i.description.mac_address)|dmac=|sinterface=|dinterface=|sip=$($i.description.src_host)|dip=$($i.description.dst_host)|snatip=|dnatip=|sname=$($i.description.src_host_reverse)|dname=$($i.description.name)|serialnumber=|login=|account=|sender=$($i.Log_Type)|recipient=|group=|domainimpacted=|domainorigin=|protnum=|protname=|sport=$($i.description.src_port)|dport=$($i.description.dst_port)|snatport=|dnatport=|augmented=|tag1=$($i.Log_Type)|tag2=|tag3=$($i.description.description)|tag4=|tag5=|tag6=|tag7=|tag8=|tag9=|tag10=|"
                    Write-IncidentLog -body $logbody
                    Write-Log -loglevel 1 -logdetail "Incident $($counter) written: $($logbody)"
                }
                Catch {
                    Write-Log -loglevel 3 -logdetail "***WARNING*** Could not format log body to output: $_"
                }
            }
        }
    }
    Catch {
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured writing incident events: $_"
    }
}

### MAIN ###

if ($IgnoreCertErrors.IsPresent) {
    Write-Log -loglevel 3 -logdetail "***WARNING*** Script invoked with IgnoreCertErrors. Certificate errors will be ignored"
}
if (($proxy -ne $null) -and ($proxy -ne "")) {
    Write-Log -loglevel 3 -logdetail "Using proxy $($proxy)"
}
$last_state = Get-State
$incidentresults = Get-IncidentEvents -LastUpdateID $last_state.incidentstate
$auditresults = Get-AuditEvents -LastUpdateID $last_state.auditstate
Write-IncidentEvents $incidentresults
Write-AuditEvents $auditresults
Write-State -IncidentState $incidentresults.last_id -AuditState $auditresults.last_id
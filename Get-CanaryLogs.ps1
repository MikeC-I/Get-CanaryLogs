<#
.SYNOPSIS
    Get-CanaryLogs.ps1 is a PowerShell script for retrieving Canary incident events from the Canary API and sending the logs as webhooks to a listener.
.DESCRIPTION
    Get-CanaryLogs.ps1 is a PowerShell script for retrieving Canary incident events from the Canary API and sending the logs as webhooks to a listener.
    Global configuration parameters are stored as JSON in Get-CanaryLogs_config.json (or whatever you want to name it, see line 21 below).
.PARAMETER IgnoreCertErrors
    Will ignore certificate errors.  Useful in environments with proxies or other HTTPS intermediaries
.EXAMPLE
    Get-CanaryLogs.ps1 -IgnoreCertErrors
.NOTES
    Change Log:
        2021/06/11 - First draft version
 #>

[CmdletBinding()]
param(
    [switch]$IgnoreCertErrors
)

$configfile = "C:\LogRhythm\Scripts\Get-CanaryLogs\Get-CanaryLogs_config.json"
$config = Get-Content -Raw $configfile | ConvertFrom-Json
$logfile = $config.logfile
$globalloglevel = $config.loglevel
$statefile = $config.statefile
$domainhash = $config.domainhash
$apitoken = $config.apitoken
$webhookendpoint = $config.webhookendpoint

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
    # Auto-rotate feature written but un-tested (will rotate logfile after 10 MB)
           
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
                    $logfilename = ((Get-Item $logdetail).Name).ToString()
                    $newfilename = "$($logfilename)"+ (Get-Date -Format "yyyyMMddhhmmss").ToString()
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

Function Get-State {
    $statefile_exists = Test-Path -Path $statefile
    [Int32]$lastUpdateID = 0
    if ($statefile_exists -eq 0) {
        Write-Log -loglevel 2 -logdetail "State file does not exist. Script will proceed with last updated_id = 0"
        $lastUpdateID = 0
    }
    Else{
        Try {
            Write-Log -loglevel 1 -logdetail "Reading last update_id from state file $($statefile)"
            $stateraw = Get-Content $statefile
            $lastUpdateID = [int]$stateraw
            Write-Log -loglevel 1 -logdetail "Retrieved last update_id of $($state) from $($statefile)"        
        }
        Catch {
            Write-Log -loglevel 3 -loglevel "***WARNING*** Could not read $($statefile). Script will proceed with last updated_id = 0"
            $lastUpdateID = 0        
        }
    }
    Return [Int32]$lastUpdateID
}

Function Write-State {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]$LastUpdateID
    )
    try {
        $state_exists = Test-Path -Path $statefile
        if ($statefile_exists -eq 1) {
            Write-Log -loglevel 1 -logdetail "Writing Last Update ID of $($LastUpdateID) to state file $($statefile)"
            $LastUpdateID | Out-File -FilePath $statefile
        }
        else {
            Write-Log -loglevel 1 -logdetail "State file does not exist. Creating $($statefile)"
            
            Write-Log -loglevel 1 -logdetail "Writing Last Update ID of $($LastUpdateID) to state file $($statefile)"
            $LastUpdateID | Out-File -FilePath $statefile
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
    $returnresult = @()
    $returnresult += $result
    $returnresult += $max_update_id
    Return ,$returnresult  # Returns an array, with the incident results as Index 0, and the max updated_id as Index 1
}

Function Send-IncidentEvents ($incidents) {
    # THIS FUNCTION IS TOTALLY UNTESTED.  I HAVE NO IDEA IF IT WILL WORK CORRECTLY
    # $incidents.incidents | ConvertTo-Json | Out-File -FilePath "C:\LogRHythm\Scripts\Get-CanaryLogs\output.txt"

    Write-Log -loglevel 2 -logdetail "Sending results to $($webhookendpoint)..."
    Try {
        $rawincidents = $incidents.incidents | ConvertTo-Json
        $result = Invoke-WebRequest -Uri $webhookendpoint -Body $rawincidents -Method POST
        Write-Log -loglevel 2 -logdetail "Incidents sent. Result: $($result.StatusCode) $($result.StatusDescription)"
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
if ($last_state.GetType().Name -ne "Int32") {  # This code is apparently necessary because of what I can only assume is a bug in PowerShell. When the logfile does not exist, for some reason the Get-State function returns a System Object type rather than an integer. I have absolutely no idea why, it makes zero sense. None. The Get-State function should explicitl return an integer every time, or at least that's how it's coded to me...I don't know man...
    [Int32]$last_state = 0
}
$results = Get-IncidentEvents -LastUpdateID $last_state
Send-IncidentEvents $results[0]
Write-State -LastUpdateID $results[1]
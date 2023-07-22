Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Web
Add-Type -AssemblyName System
Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@

function Connect-BTV {
    param(
        [Parameter(Mandatory=$true)][string]$serverURL,
        [Parameter(Mandatory=$false)][string]$licenseKey,
        [Parameter(Mandatory=$false)][string]$apiUser = 'BeyondTV.PSHelper',
        [Parameter(Mandatory=$false)][string]$apiPassword,
        [Parameter(Mandatory=$false)][string]$expiry = 15

    )
    $beyondTV.serverURL = $serverURL
    $beyondTV.licenseKey = $licenseKey
    $beyondTV.apiUser = $apiUser
    New-Item -Path $beyondTV.registryURL -Force | Out-null
    New-ItemProperty -Path $beyondTV.registryURL -Name serverURL -Value $serverURL | Out-Null
    if ($apiPassword) {
        $beyondTV.apiPassword = $apiPassword
        $tempArray = $apiPassword | % {[byte] $_}
        $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($tempArray, `
            $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        New-ItemProperty -Path $beyondTV.registryURL -Name ApiPassword -Value $encrypted | Out-Null
    }
    New-ItemProperty -Path $beyondTV.registryURL -Name apiUser -Value $apiUser | Out-Null
    New-ItemProperty -Path $beyondTV.registryURL -Name expiry -Value $expiry | Out-Null

    #Get-BTVAuthTicket | Out-Null
    write-host "Connected to BeyondTV server at $($beyondTV.serverURL)`n"
}

function Disconnect-BTV {
    Remove-ItemProperty -Path $beyondTV.registryURL -Name apiUser -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -Path $beyondTV.registryURL -Name apiPassword -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -Path $beyondTV.registryURL -Name AuthTicket -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -Path $beyondTV.registryURL -Name Expires -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -Path $beyondTV.registryURL -Name expiry -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty -Path $beyondTV.registryURL -Name serverURL -ErrorAction SilentlyContinue | Out-Null
    $beyondTV.serverURL = $null
    $beyondTV.apiPassword = $null
    $beyondTV.apiUser = $null
    $beyondTV.AuthTicket = $null
    $beyondTV.Expires = $null
    $beyondTV.expiry = $null
}

function Get-BTVAuthTicket {
    if (-not $beyondTV.expires) {
        $beyondTV.expires = [DateTime]::Now
    }
    $uri = $beyondTV.serverURL + "/BTVLicenseManager.asmx"
    $btvLicenseManager = New-WebServiceProxy -Uri $uri
    if ([DateTime]$beyondTV.expires -lt [DateTime]::Now.AddMinutes(1)) {
        $beyondTv.authTicket = ($btvLicenseManager.Logon($beyondTV.licenseKey,$beyondTV.apiUser,$beyondTV.apiPassword).Properties | where {$_.Name -eq 'AuthTicket'}).Value
        Set-ItemProperty -Path $beyondTV.registryURL -Name AuthTicket -Value $beyondTV.authTicket | Out-Null
        $beyondTV.expires = [DateTime]::Now.AddMinutes($beyondTV.expiry)
    } elseif ([DateTime]$beyondTV.expires -lt [DateTime]::Now.AddMinutes($beyondTV.expiry / 2)) {
        $btvLicenseManager.RenewLogonSession( $beyondTV.authTicket) | Out-Null
        $beyondTV.expires = [DateTime]::Now.AddMinutes($beyondTV.expiry)
    }
    Set-ItemProperty -Path $beyondTV.registryURL -Name Expires -Value $beyondTV.expires | Out-Null
    $beyondTV.authTicket
}

function Get-BTVUnifiedLineup {
    $uri = $beyondTV.serverURL + "/BTVSettings.asmx"
    $BtvSettings = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $xmlLineup = $btvSettings.GetUnifiedLineup($ticket)
    $channels = $xmlLineup | Select-XML -XPath '/ChannelCollection/Channel' | Select-Object -ExpandProperty Node
    foreach ($channelBag in $channels) {
        $channel = New-Object PSObject
        foreach ($property in $channelBag.property) {
            $channel | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $channel
    }
}

function Get-BTVPermissions {
    $uri = $beyondTV.serverURL + "/BTVLicenseManager.asmx"
    $btvLicenseManager = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $response = $btvLicenseManager.GetPermissionsForTicket($ticket)
    $properties = $response | Select-XML -Xpath '/PropertyCollection/Property' |  Select-Object -ExpandProperty Node
    $btvPermissions = New-Object PSObject
    foreach ($property in $properties) {
        $btvPermissions | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
    }
    $btvPermissions
}

function Start-BTVGuideUpdate {
    $uri = $beyondTV.serverURL + "/BTVGuideUpdater.asmx"
    $btvGuideUpdater = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $btvGuideUpdater.SetProperty($ticket,'UpdateType','Clean') | Out-null
    $btvGuideUpdater.StartUpdate($ticket)
}

function Get-BTVGuideStatus {
    $uri = $beyondTV.serverURL + "/BTVGuideUpdater.asmx"
    $btvGuideUpdater = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $state =''
    $message = ''
    $progressResult = $btvGuideUpdater.GetProgress($ticket, [ref]$state, [ref]$message)
    $lastAttemptUpdate = [datetime]::FromFileTimeUtc($btvGuideUpdater.GetLastAttemptedUpdate($ticket))
    $lastSuccessfulUpdate = [datetime]::FromFileTimeUtc($btvGuideUpdater.GetLastSuccessfulUpdate($ticket))
    $nextAttemptedUpdate = [datetime]::FromFileTimeUtc($btvGuideUpdater.GetNextAttemptedUpdate($ticket))
    $btvGuideProgress = New-Object PSObject
    $btvGuideProgress | Add-member -NotePropertyName 'GuideUpdaterResult' -NotePropertyValue $progressResult
    $btvGuideProgress | Add-member -NotePropertyName 'GuideUpdaterState' -NotePropertyValue $state
    $btvGuideProgress | Add-member -NotePropertyName 'GuideUpdaterMessage' -NotePropertyValue $message
    $btvGuideProgress | Add-member -NotePropertyName 'LastAttemptUpdate' -NotePropertyValue $lastAttemptUpdate
    $btvGuideProgress | Add-member -NotePropertyName 'LastSuccessfulUpdate' -NotePropertyValue $lastSuccessfulUpdate
    $btvGuideProgress | Add-member -NotePropertyName 'NextAttemptedUpdate' -NotePropertyValue $nextAttemptedUpdate
    $btvGuideProgress
}

function Get-BTVUpcomingRecordings {
    $uri = $beyondTV.serverURL + "/BTVScheduler.asmx"
    $BTVScheduler = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $recordings = $BTVScheduler.GetUpcomingRecordings($ticket)
    foreach ($recordingBag in $recordings) {
        $recording = New-Object PSObject
        foreach ($property in $recordingBag.properties) {
            $recording | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $recording
    }
}    

$beyondTV = [ordered]@{
    registryURL = "HKCU:\Software\Snapstream\BeyondTV.PSHelper"
    serverURL = ""
    licenseKey = ""
    apiUser = ""
    apiPassword = ""
    authTicket = ""
    expiry = 0
    expires = ""
}
New-Variable -Name beyondTV -Value $beyondTV -Scope script -Force
$registryKey = (Get-ItemProperty -Path $beyondTV.registryURL -ErrorAction SilentlyContinue)
if ($registryKey -eq $null) {
    Write-Warning "Autoconnect failed.  API key not found in registry.  Use Connect-BTV to connect manually."
} else {
    $beyondTV.serverURL = $registryKey.serverURL
    if ($registryKey.apiPassword) {
        $encrypted = $registryKey.apiPassword
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, `
            $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $decrypted | % { $apiBase64 += [char] $_} | Out-Null
        $beyondTV.apiPassword = $decrypted
    } else {
        $beyondTV.apiPassword = ''
    }
    $beyondTV.authTicket = $registryKey.authTicket
    $beyondTV.apiUser = $registryKey.apiUser
    $beyondTV.expires = [DateTime]::$registryKey.expires
    $beyondTV.expiry = $registryKey.expiry
    if (-not $beyondTV.expires) {
        $beyondTV.expires = [DateTime]::Now
    }
    #Get-BTVAuthTicket | Out-Null
    write-host "Connected to BeyondTV server at $($beyondTV.serverURL)`n"
}
Write-host "Cmdlets added:`n$(Get-Command | where {$_.ModuleName -eq 'beyondTV.PSHelper'})`n"
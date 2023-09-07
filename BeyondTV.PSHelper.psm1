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
    New-ItemProperty -Path $beyondTV.registryURL -Name licenseKey -Value $licenseKey | Out-Null
    Get-BTVAuthTicket | Out-Null
    write-host "Connected to BeyondTV server at $($beyondTV.serverURL)`n"
}

function Disconnect-BTV {
    if ($beyondTV.authTicket) {
        $uri = $beyondTV.serverURL + "/BTVLicenseManager.asmx"
        $btvLicenseManager = New-WebServiceProxy -Uri $uri
        $ticket = Get-BTVAuthTicket
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
        $btvLicenseManager.Logoff($ticket)
    }
}

function Get-BTVAuthTicket {
    if (-not $beyondTV.expires) {
        $beyondTV.expires = [DateTime]::Now
    }
    $uri = $beyondTV.serverURL + "/BTVLicenseManager.asmx"
    $btvLicenseManager = New-WebServiceProxy -Uri $uri
    if ([DateTime]$beyondTV.expires -lt [DateTime]::Now.AddMinutes(1)) {
        $btvLogonProperties = $btvLicenseManager.Logon($beyondTV.licenseKey,$beyondTV.apiUser,$beyondTV.apiPassword)

        $beyondTv.authTicket = ($btvLogonProperties.properties | where {$_.Name -eq 'AuthTicket'}).Value
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

function Get-BTVDevices {
    $uri = $beyondTV.serverURL + "/BTVSettings.asmx"
    $BtvSettings = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $devices = $btvSettings.GetDevices($ticket)
    foreach ($deviceBag in $devices) {
        $device = New-Object PSObject
        foreach ($property in $deviceBag.properties) {
            $device | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $device
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
    param(
        [Parameter(Mandatory=$false)][string]$updateType = 'Clean'
    )
    $uri = $beyondTV.serverURL + "/BTVGuideUpdater.asmx"
    $btvGuideUpdater = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $btvGuideUpdater.SetProperty($ticket,'UpdateType',$updateType) | Out-null
    $btvGuideUpdater.StartUpdate($ticket)
}

function Import-BTVRemoteRecordings {
    $uri = $beyondTV.serverURL + "/BTVGuideUpdater.asmx"
    $btvGuideUpdater = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $btvGuideUpdater.GetRemoteRecordings($ticket)
}

function Get-BTVGuideCatagories {
    param(
        [Parameter(Mandatory=$false)][string]$topCatagory = ''
    )
    $uri = $beyondTV.serverURL + "/BTVGuideData.asmx"
    $btvGuideData = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $catagories = $btvGuideData.GetCategories($ticket,$topCatagory)
    foreach ($catagoryBag in $catagories) {
         $catagory = New-Object PSObject
         foreach ($property in $catagoryBag.properties) {
            $catagory | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
         }
         $catagory
    }
}

function Get-BTVGuideStatus {
    $uri = $beyondTV.serverURL + "/BTVGuideUpdater.asmx"
    $btvGuideUpdater = New-WebServiceProxy -Uri $uri
    $uri = $beyondTV.serverURL + "/BTVGuideData.asmx"
    $btvGuideData = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $state =''
    $message = ''
    $progressResult = $btvGuideUpdater.GetProgress($ticket, [ref]$state, [ref]$message)
    $lastAttemptedUpdate = [datetime]::FromFileTimeUtc($btvGuideUpdater.GetLastAttemptedUpdate($ticket)).ToLocalTime()
    $lastSuccessfulUpdate = [datetime]::FromFileTimeUtc($btvGuideUpdater.GetLastSuccessfulUpdate($ticket)).ToLocalTime()
    $nextAttemptedUpdate = [datetime]::FromFileTimeUtc($btvGuideUpdater.GetNextAttemptedUpdate($ticket)).ToLocalTime()
    $guideDataExtents = ''
    $btvGuideData.GetDataExtents($ticket,[ref]$guideDataExtents) | Out-Null
    $guideDataExtents = [datetime]::FromFileTimeUtc($guideDataExtents).ToLocalTime()
    $btvGuideProgress = New-Object PSObject
    $btvGuideProgress | Add-member -NotePropertyName 'GuideUpdaterResult' -NotePropertyValue $progressResult
    $btvGuideProgress | Add-member -NotePropertyName 'GuideUpdaterState' -NotePropertyValue $state
    $btvGuideProgress | Add-member -NotePropertyName 'GuideUpdaterMessage' -NotePropertyValue $message
    $btvGuideProgress | Add-member -NotePropertyName 'LastAttemptedUpdate' -NotePropertyValue $lastAttemptedUpdate
    $btvGuideProgress | Add-member -NotePropertyName 'LastSuccessfulUpdate' -NotePropertyValue $lastSuccessfulUpdate
    $btvGuideProgress | Add-member -NotePropertyName 'NextAttemptedUpdate' -NotePropertyValue $nextAttemptedUpdate
    $btvGuideProgress | Add-member -NotePropertyName 'GuideDataExtents' -NotePropertyValue $guideDataExtents
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

function Get-BTVRejectedRecordings {
    $uri = $beyondTV.serverURL + "/BTVScheduler.asmx"
    $BTVScheduler = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $recordings = $BTVScheduler.GetRejectedRecordings($ticket)
    foreach ($recordingBag in $recordings) {
        $recording = New-Object PSObject
        foreach ($property in $recordingBag.properties) {
            $recording | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $recording
    }
}

function Get-BTVActiveRecordings {
    $uri = $beyondTV.serverURL + "/BTVDispatcher.asmx"
    $btvDispatcher = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $recordings = $btvDispatcher.GetActiveRecordings($ticket)
    foreach ($recordingBag in $recordings) {
        $recording = New-Object PSObject
        foreach ($property in $recordingBag.properties) {
            $recording | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $recording
    }
}

function Get-BTVLiveTVSessions {
    $uri = $beyondTV.serverURL + "/BTVLiveTVManager.asmx"
    $btvDispatcher = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $sessions = $btvDispatcher.GetSessions($ticket)
    foreach ($sessionBag in $sessions) {
        $session = New-Object PSObject
        foreach ($property in $sessionBag.properties) {
            $session | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $session
    }
}

function Get-BTVSeries {
    $uri = $beyondTV.serverURL + "/BTVLibrary.asmx"
    $BTVLibrary = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $allSeries = $BTVLibrary.GetSeries($ticket)
    foreach ($seriesBag in $allSeries) {
        $series = New-Object PSObject
        foreach ($property in $seriesBag.properties) {
           $series | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $series
    }
}

function Get-BTVUniqueStationIDExtents {
    $uniqueChannelIDs = (Get-BTVUnifiedLineup).UniqueChannelID | Sort
    $uniqueStationIDExtents = New-Object PSObject
    $uniqueStationIDExtents | Add-member -NotePropertyName uniqueChannelIDStart -NotePropertyValue $($uniqueChannelIDs | Select-Object -First 1)
    $uniqueStationIDExtents | Add-member -NotePropertyName uniqueChannelIDEnd -NotePropertyValue $($uniqueChannelIDs | Select-Object -Last 1)
    $uniqueStationIDExtents
}

function Get-BTVEpisodesByStationAndTime {
    [CmdletBinding(DefaultParameterSetName='byChannelID')]
    param(
        [Parameter(Mandatory=$false,ParameterSetName='byChannelID')][string]$uniqueChannelIDStart,
        [Parameter(Mandatory=$false,ParameterSetName='byChannelID')][string]$uniqueChannelIDEnd,
        [Parameter(Mandatory=$false,ParameterSetName='byCallSign')][string]$stationCallSign,
        [Parameter(Mandatory=$false)][string]$timeStart,
        [Parameter(Mandatory=$false)][string]$timeEnd
    )
    if ((-not $uniqueChannelIDStart) -or (-not $uniqueChannelIDEnd)) {
        $uniqueChannelIDExtents = Get-BTVUniqueStationIDExtents
        if (-not $uniqueChannelIDStart) {
            $uniqueChannelIDStart = $uniqueChannelIDExtents.uniqueChannelIDStart
        }
        if (-not $uniqueChannelIDEnd) {
            $uniqueChannelIDEnd = $uniqueChannelIDExtents.uniqueChannelIDEnd
        }
    }
    if (-not $timeStart) {
        $timeStart = (Get-Date).ToFileTime()
    }
    if (-not $timeEnd) {
        $timeEnd = (Get-Date).ToFileTime()
    }
    $uri = $beyondTV.serverURL + "/BTVGuideData.asmx"
    $btvGuideData = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    if ($stationCallSign) {
        $uniqueChannelIDs = (Get-BTVUnifiedLineup | where {$_.StationCallSign -eq $stationCallSign}).UniqueChannelID  
        foreach ($uniqueChannelID in $uniqueChannelIDs) {
            $episodes = $btvGuideData.GetEpisodesByStationAndTimeRanges($ticket,$uniqueChannelID,$uniqueChannelID,$timeStart,$timeEnd)
            foreach ($episodeBag in $episodes) {
                $episode = New-Object PSObject
                foreach ($property in $episodeBag.properties) {
                    $episode | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
                }
                $episode
            }
        }
    } else {
        $episodes = $btvGuideData.GetEpisodesByStationAndTimeRanges($ticket,$uniqueChannelIDStart,$uniqueChannelIDEnd,$timeStart,$timeEnd)
        foreach ($episodeBag in $episodes) {
            $episode = New-Object PSObject
            foreach ($property in $episodeBag.properties) {
                $episode | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
            }
            $episode
        }
    }
}

function Find-BTVEpisodesByKeyword {
    param(
        [Parameter(Mandatory=$true)][string]$keywords
    )
    $uri = $beyondTV.serverURL + "/BTVGuideData.asmx"
    $btvGuideData = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $episodes = $btvGuideData.GetEpisodesByKeyword($ticket,$keywords)
    foreach ($episodeBag in $episodes) {
        $episode = New-Object PSObject
        foreach ($property in $episodeBag.properties) {
            $episode | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $episode
    }
}

function Find-BTVEpisodesByStation {
    [CmdletBinding(DefaultParameterSetName='byCallSign')]
    param(
        [Parameter(Mandatory=$true,ParameterSetName='byChannelID')][string]$uniqueChannelID,
        [Parameter(Mandatory=$true,ParameterSetName='byCallSign')][string]$stationCallSign
    )
    $uri = $beyondTV.serverURL + "/BTVGuideData.asmx"
    $btvGuideData = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    if ($stationCallSign) {
        $uniqueChannelIDs = (Get-BTVUnifiedLineup | where {$_.StationCallSign -eq $stationCallSign}).UniqueChannelID  
        foreach ($uniqueChannelID in $uniqueChannelIDs) {
            $episodes = $btvGuideData.GetEpisodesByStation($ticket,$uniqueChannelID)
            foreach ($episodeBag in $episodes) {
                $episode = New-Object PSObject
                foreach ($property in $episodeBag.properties) {
                    $episode | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
                }
                $episode
            }
        }
    } else {
        $episodes = $btvGuideData.GetEpisodesByStation($ticket,$uniqueChannelID)
        foreach ($episodeBag in $episodes) {
            $episode = New-Object PSObject
            foreach ($property in $episodeBag.properties) {
                $episode | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
            }
            $episode
        }
    }
}

function Find-BTVSeriesByCatagory {
    param(
        [Parameter(Mandatory=$true)][string]$catagory,
        [Parameter(Mandatory=$false)][string]$subCatagory
    )
    $uri = $beyondTV.serverURL + "/BTVGuideData.asmx"
    $btvGuideData = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    if ($subCatagory.IsPresent) {
        $allSeries = $btvGuideData.GetSeriesByCategory($ticket,$catagory,$subCatagory)
        foreach ($seriesBag in $allSeries) {
            $series = New-Object PSObject
            foreach ($property in $seriesBag.properties) {
                $series | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
            }
            $series
        }
    } else {
        $subCatagories = (Get-BTVGuideCatagories -topCatagory $catagory).Category | where {$_ -ne ''}
        foreach ($subCatagory in $subCatagories) {
            $allSeries = $btvGuideData.GetSeriesByCategory($ticket,$catagory,$subCatagory)
            foreach ($seriesBag in $allSeries) {
                $series = New-Object PSObject
                foreach ($property in $seriesBag.properties) {
                    $series | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
                }
                $series
            }
        }
    }
}

function Find-BTVSeriesByKeyword {
    param(
        [Parameter(Mandatory=$true)][string]$keywords
    )
    $uri = $beyondTV.serverURL + "/BTVGuideData.asmx"
    $btvGuideData = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $allSeries = $btvGuideData.GetSeriesByKeyword($ticket,$keywords)
    foreach ($seriesBag in $allSeries) {
        $series = New-Object PSObject
        foreach ($property in $seriesBag.properties) {
            $series | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $series
    }
}

function Get-BTVFolders {
    param(
        [Parameter(Mandatory=$false)][string]$folder = ''
    )
    $uri = $beyondTV.serverURL + "/BTVLibrary.asmx"
    $btvLibrary = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $folders = $btvLibrary.GetFolders($ticket,$folder)
    foreach ($folderBag in $folders) {
        $btvFolder = New-Object PSObject
        foreach ($property in $folderBag.properties) {
            $btvFolder | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $btvFolder
    }
}

function Get-BTVRecordings {
    $uri = $beyondTV.serverURL + "/BTVLibrary.asmx"
    $BTVLibrary = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $recordings = $BTVLibrary.FlatViewByDate($ticket)
    foreach ($recordingBag in $recordings) {
        $recording = New-Object PSObject
        foreach ($property in $recordingBag.properties) {
            $recording | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $recording
    }
}

function New-BTVLogEntry {
    param(
        [Parameter(Mandatory=$true)][int]$errorCode,
        [Parameter(Mandatory=$false)][int]$unique = 1,
        [Parameter(Mandatory=$false)][int]$uniqueDesc = 1,
        [Parameter(Mandatory=$true)][string]$errorDescription
    )
    $uri = $beyondTV.serverURL + "/BTVLog.asmx"
    $BTVLog = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $BTVLog.LogError($ticket,$errorCode,$unique,$uniqueDesc,$errorDescription)
}

function Get-BTVCommands {
    (Get-Command | where {$_.ModuleName -eq 'beyondTV.PSHelper'}).Name
}

function Get-BTVTaskListCount {
    $uri = $beyondTV.serverURL + "/BTVBatchProcessor.asmx"
    $BTVTaskListProcessor = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $BTVTaskListProcessor.GetCount($ticket)
}

function Get-BTVJobs {
    $uri = $beyondTV.serverURL + "/BTVScheduler.asmx"
    $BTVScheduler = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $jobBags = $BTVScheduler.GetJobs($ticket)
    foreach ($jobBag in $jobBags) {
        $btvJob = New-Object PSObject
        foreach ($property in $jobBag.properties) {
            $btvJob | Add-member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        }
        $btvJob
    }
}

function Get-BTVTaskLists {
    param(
        [Parameter(Mandatory=$false)][int]$taskIndex,
        [Parameter(Mandatory=$false)][switch]$showHidden
    )
    $taskListCount = Get-BTVTaskListCount
    if ($PSBoundParameters.ContainsKey('taskIndex') -and (($taskIndex + 1) -gt $taskListCount)) {
        break
    }
    $uri = $beyondTV.serverURL + "/BTVBatchProcessor.asmx"
    $btvTaskListProcessor = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    if ($PSBoundParameters.ContainsKey('taskIndex')) {
        $taskListCount = $taskIndex + 1
    } else {
        $taskIndex = 0
    }
    for($taskIndex; $taskIndex -lt $taskListCount; $taskIndex++) {
        $xmlTaskList = $btvTaskListProcessor.ItemByIndex($ticket, $taskIndex)
        $taskList = $xmlTaskList | Select-XML -XPath '/BatchList' | Select-Object -ExpandProperty Node
        if ($showHidden.IsPresent -or $taskList.Hidden -eq '0') {
            $taskList
        }
    }
}

function New-BTVRecordingJob {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)][string]$rules,
        [Parameter(ValueFromPipelineByPropertyName)][string]$uniqueChannelID,
        [Parameter(Mandatory=$false)][string]$epgRepeat,
        [Parameter(ValueFromPipelineByPropertyName)][string]$epgId,
        [Parameter(ValueFromPipelineByPropertyName)][string]$seriesTitle,
        [Parameter(ValueFromPipelineByPropertyName)][string]$seriesDescription,
        [Parameter(ValueFromPipelineByPropertyName)][string]$episodeTitle,
        [Parameter(ValueFromPipelineByPropertyName)][string]$episodeDescription,
        [Parameter(ValueFromPipelineByPropertyName)][string]$stationNumber,
        [Parameter(ValueFromPipelineByPropertyName)][string]$channel,
        [Parameter(ValueFromPipelineByPropertyName)][string]$start,
        [Parameter(ValueFromPipelineByPropertyName)][string]$genre,
        [Parameter(Mandatory=$false)][string]$timeParameterHour,
        [Parameter(Mandatory=$false)][string]$timeParameterMinute,
        [Parameter(Mandatory=$false)][string]$timeParameterDayOfWeek,
        [Parameter(Mandatory=$false)][string]$timeParameterMonth,
        [Parameter(Mandatory=$false)][string]$timeParameterYear,
        [Parameter(Mandatory=$false)][string]$timeParameterDay,
        [Parameter(Mandatory=$false)][string]$duration = '',
        [Parameter(Mandatory=$false)][string]$extendStart = '0',
        [Parameter(Mandatory=$false)][string]$extendEnd = '0',
        [Parameter(Mandatory=$false)][string]$manualRepeat,
        [Parameter(Mandatory=$false)][string]$keyword,
        [Parameter(Mandatory=$false)][string]$recordAnyChannel = '0'
    )
    $btvJob = New-Object PSObject
    $btvJob | Add-member -NotePropertyName 'GUID' -NotePropertyValue ([guid]::NewGuid()).Guid
    $btvJob | Add-member -NotePropertyName 'Rules' -NotePropertyValue $rules
    if ($episodeTitle) {
        $btvJob | Add-member -NotePropertyName 'Title' -NotePropertyValue $episodeTitle
    } else {
        $btvJob | Add-member -NotePropertyName 'Title' -NotePropertyValue $seriesTitle
    }
    $btvJob | Add-member -NotePropertyName 'DisplayTitle' -NotePropertyValue $btvJob.Title
    $btvJob | Add-member -NotePropertyName 'SeriesTitle' -NotePropertyValue $seriesTitle
    $btvJob | Add-member -NotePropertyName 'EpisodeTitle' -NotePropertyValue $episodeTitle
    $btvJob | Add-member -NotePropertyName 'SeriesDescription' -NotePropertyValue $seriesDescription
    $btvJob | Add-member -NotePropertyName 'EpisodeDescription' -NotePropertyValue $episodeDescription
    $btvJob | Add-member -NotePropertyName 'ExtendStart' -NotePropertyValue $extendStart
    $btvJob | Add-member -NotePropertyName 'ExtendEnd' -NotePropertyValue $extendEnd
    $btvJob | Add-member -NotePropertyName 'Duration' -NotePropertyValue $duration
    $btvJob | Add-member -NotePropertyName 'RecordAnyChannel' -NotePropertyValue $recordAnyChannel
    $btvJob | Add-member -NotePropertyName 'StartDateTime' -NotePropertyValue $start
    $btvJob | Add-member -NotePropertyName 'Genre' -NotePropertyValue $genre
    if (($rules -eq 'EPG') -or ($rules -eq 'Keyword'))  {
        $station = Get-BTVUnifiedLineup | where {$_.uniqueChannelID -eq $uniqueChannelID}
        $btvJob | Add-member -NotePropertyName 'UniqueChannelID' -NotePropertyValue $uniqueChannelID
        $btvJob | Add-member -NotePropertyName 'StationNumber' -NotePropertyValue $station.stationNumber
        $btvJob | Add-member -NotePropertyName 'Channel' -NotePropertyValue $station.TMSChannel
        $btvJob | Add-member -NotePropertyName 'EPGRepeat' -NotePropertyValue $epgRepeat
        $btvJob | Add-member -NotePropertyName 'EPGID' -NotePropertyValue $epgId
        $btvJob | Add-member -NotePropertyName 'Keyword' -NotePropertyValue $keyword
    } elseif ($rules -eq 'Manual') {
        $btvJob | Add-member -NotePropertyName 'TimeParameterHour' -NotePropertyValue $timeParameterHour
        $btvJob | Add-member -NotePropertyName 'TimeParameterMinute' -NotePropertyValue $timeParameterMinute
        $btvJob | Add-member -NotePropertyName 'TimeParameterDayOfWeek' -NotePropertyValue $timeParameterDayOfWeek
        $btvJob | Add-member -NotePropertyName 'TimeParameterMonth' -NotePropertyValue $timeParameterMonth
        $btvJob | Add-member -NotePropertyName 'TimeParameterYear' -NotePropertyValue $timeParameterYear
        $btvJob | Add-member -NotePropertyName 'TimeParameterDay' -NotePropertyValue $timeParameterDay
        $btvJob | Add-member -NotePropertyName 'Channel' -NotePropertyValue $channel
        $btvJob | Add-member -NotePropertyName 'StationNumber' -NotePropertyValue $channel
    }
    $btvJob | Add-member -NotePropertyName 'DisplayedChannelID' -NotePropertyValue $btvJob.StationNumber
    $btvJob
}

function Add-BTVRecordingJob {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipeline)][PSObject]$recordingJob,
        [Parameter(Mandatory=$false)][int]$highestPriority = 0
    )
    $uri = $beyondTV.serverURL + "/BTVScheduler.asmx"
    $BTVScheduler = New-WebServiceProxy -Uri $uri
    $ticket = Get-BTVAuthTicket
    $jobBag = New-Object $($BTVScheduler.getType().namespace + ".PVSPropertyBag")
    $jobProperties = $recordingJob.PSObject.Properties
    foreach ( $property in $jobProperties ) {
        $bagProperty = New-Object $($BTVScheduler.getType().namespace + ".PVSProperty")
        $bagProperty.Name = $property.Name
        $bagProperty.Value = $property.Value
        $jobBag.Properties += $bagProperty
    }
    $BTVScheduler.AddRecordingJob($ticket,$jobBag,$highestPriority)
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
    $beyondTV.licenseKey = $registryKey.licenseKey
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
$TestDurationMs = 60000
$TestRateHz = 100
$TestPayloadBytes = 1400
$TestMode = "rx"
$TestTargetMbps = 45
$DefaultTestPort = 9123
$HeadsetHttpPort = 9124

$RunCount = 1
$OutputDir = "C:\temp\network-test-runs"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$RawLogFile = Join-Path $OutputDir "network-test-raw-$Timestamp.jsonl"
$SummaryLogFile = Join-Path $OutputDir "network-test-summary-$Timestamp.txt"

# Default behavior: run a single test profile per headset.
# To run simultaneous tests on the same headset, replace this array with multiple
# profiles that use unique UDP ports.
$TestProfiles = @(
    @{
        Name = "rtt"
        Mode = "rtt"
        Port = 9123
        DurationMs = 60000
        RateHz = 100
        PayloadBytes = 128
    },
    @{
        Name = "rx"
        Mode = "rx"
        Port = 9125
        DurationMs = 60000
        PayloadBytes = 1400
        TargetMbps = 45
    }
)

# Example simultaneous RTT + RX profile set:
# $TestProfiles = @(
#     @{
#         Name = "rtt"
#         Mode = "rtt"
#         Port = 9123
#         DurationMs = 60000
#         RateHz = 100
#         PayloadBytes = 64
#     },
#     @{
#         Name = "rx"
#         Mode = "rx"
#         Port = 9125
#         DurationMs = 60000
#         PayloadBytes = 1400
#         TargetMbps = 45
#     }
# )

$siteID = '176'

# Launch one remote job per PC/headset pair.
$ipList = @(
# rm1
"10.$siteID.1.101","10.$siteID.1.102","10.$siteID.1.103","10.$siteID.1.104","10.$siteID.1.105","10.$siteID.1.106",
# rm2
"10.$siteID.2.101","10.$siteID.2.102","10.$siteID.2.103","10.$siteID.2.104","10.$siteID.2.105","10.$siteID.2.106",
# rm3
"10.$siteID.3.101","10.$siteID.3.102","10.$siteID.3.103","10.$siteID.3.104","10.$siteID.3.105","10.$siteID.3.106",
# rm4
"10.$siteID.4.101","10.$siteID.4.102","10.$siteID.4.103","10.$siteID.4.104","10.$siteID.4.105","10.$siteID.4.106"
)

$headsetsIP = @(
# rm1
"10.$siteID.1.151","10.$siteID.1.152","10.$siteID.1.153","10.$siteID.1.154","10.$siteID.1.155","10.$siteID.1.156",
# rm2
"10.$siteID.2.151","10.$siteID.2.152","10.$siteID.2.153","10.$siteID.2.154","10.$siteID.2.155","10.$siteID.2.156",
# rm3
"10.$siteID.3.151","10.$siteID.3.152","10.$siteID.3.153","10.$siteID.3.154","10.$siteID.3.155","10.$siteID.3.156",
# rm4
"10.$siteID.4.151","10.$siteID.4.152","10.$siteID.4.153","10.$siteID.4.154","10.$siteID.4.155","10.$siteID.4.156"
)

$cred = New-Object System.Management.Automation.PSCredential("SandboxVR",(New-Object System.Security.SecureString))

function Get-MaxProfileDurationMs {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Profiles,
        [int]$FallbackDurationMs
    )

    $durations = foreach ($profile in $Profiles) {
        if ($null -eq $profile) {
            continue
        }

        if ($profile -is [System.Collections.IDictionary]) {
            if ($profile.Contains("DurationMs") -and $null -ne $profile["DurationMs"]) {
                [int]$profile["DurationMs"]
            }
            continue
        }

        $durationProperty = $profile.PSObject.Properties["DurationMs"]
        if ($null -ne $durationProperty -and $null -ne $durationProperty.Value) {
            [int]$durationProperty.Value
        }
    }

    $maxDuration = ($durations | Measure-Object -Maximum).Maximum
    if ($null -eq $maxDuration -or $maxDuration -le 0) {
        return $FallbackDurationMs
    }

    [int]$maxDuration
}

$scriptBlock = {
param(
    [Parameter(Mandatory = $true)]
    [string]$HeadsetAddress,
    [string]$ResponderAddress = "",
    [int]$HeadsetHttpPort = 9124,
    [object[]]$TestProfiles
)

function Get-LocalIPv4 {
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -notlike "169.254.*" -and
            $_.IPAddress -ne "127.0.0.1"
        } |
        Sort-Object InterfaceMetric |
        Select-Object -First 1 -ExpandProperty IPAddress
}

function Normalize-TestProfile {
    param(
        [Parameter(Mandatory = $true)]
        $Profile,
        [int]$Index
    )

    $mode = [string]$Profile.Mode
    if ([string]::IsNullOrWhiteSpace($mode)) {
        throw "Test profile at index $Index is missing Mode."
    }

    $mode = $mode.ToLowerInvariant()
    if ($mode -notin @("rtt","rx","throughput")) {
        throw "Test profile '$mode' at index $Index has an invalid Mode."
    }

    $name = [string]$Profile.Name
    if ([string]::IsNullOrWhiteSpace($name)) {
        $name = "{0}-{1}" -f $mode,$Index
    }

    $port = 9123
    if ($null -ne $Profile.Port -and [string]::IsNullOrWhiteSpace([string]$Profile.Port) -eq $false) {
        $port = [int]$Profile.Port
    }

    $durationMs = 10000
    if ($null -ne $Profile.DurationMs -and [string]::IsNullOrWhiteSpace([string]$Profile.DurationMs) -eq $false) {
        $durationMs = [int]$Profile.DurationMs
    }

    $rateHz = 50
    if ($null -ne $Profile.RateHz -and [string]::IsNullOrWhiteSpace([string]$Profile.RateHz) -eq $false) {
        $rateHz = [int]$Profile.RateHz
    }

    $payloadBytes = 64
    if ($null -ne $Profile.PayloadBytes -and [string]::IsNullOrWhiteSpace([string]$Profile.PayloadBytes) -eq $false) {
        $payloadBytes = [int]$Profile.PayloadBytes
    }

    $targetMbps = 45.0
    if ($null -ne $Profile.TargetMbps -and [string]::IsNullOrWhiteSpace([string]$Profile.TargetMbps) -eq $false) {
        $targetMbps = [double]$Profile.TargetMbps
    }

    $expectedPackets = -1
    if ($null -ne $Profile.ExpectedPackets -and [string]::IsNullOrWhiteSpace([string]$Profile.ExpectedPackets) -eq $false) {
        $expectedPackets = [int]$Profile.ExpectedPackets
    }

    [pscustomobject]@{
        Name = $name
        Mode = $mode
        Port = $port
        DurationMs = $durationMs
        RateHz = $rateHz
        PayloadBytes = $payloadBytes
        TargetMbps = $targetMbps
        ExpectedPackets = $expectedPackets
        NeedsResponder = ($mode -ne "rx")
    }
}

function New-TestId {
    param(
        [string]$ProfileName,
        [string]$Mode,
        [int]$Port
    )

    $safeName = ($ProfileName -replace "[^A-Za-z0-9-]","-").Trim("-")
    if ([string]::IsNullOrWhiteSpace($safeName)) {
        $safeName = $Mode
    }

    $suffix = [guid]::NewGuid().ToString("N").Substring(0,8)
    "{0}-{1}-{2}-{3}" -f $safeName,$Mode,$Port,$suffix
}

function New-QueryString {
    param([hashtable]$Params)

    $pairs = foreach ($key in $Params.Keys) {
        $value = $Params[$key]
        if ($null -eq $value) {
            continue
        }

        $stringValue = [string]$value
        if ($stringValue.Length -eq 0) {
            continue
        }

        "{0}={1}" -f [uri]::EscapeDataString([string]$key),[uri]::EscapeDataString($stringValue)
    }

    $pairs -join "&"
}

function Invoke-ApiRequest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [int]$TimeoutSec = 5
    )

    $statusCode = -1
    $content = $null

    try {
        $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec $TimeoutSec -Uri $Uri -ErrorAction Stop
        $statusCode = [int]$response.StatusCode
        $content = $response.Content
    }
    catch {
        $resp = $_.Exception.Response
        if ($null -eq $resp) {
            throw
        }

        try {
            $statusCode = [int]$resp.StatusCode
        }
        catch {
            $statusCode = -1
        }

        try {
            $stream = $resp.GetResponseStream()
            if ($null -ne $stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                try {
                    $content = $reader.ReadToEnd()
                }
                finally {
                    $reader.Dispose()
                }
            }
        }
        catch {
            $content = $null
        }
    }

    $json = $null
    if ($content) {
        try {
            $json = $content | ConvertFrom-Json
        }
        catch {
            $json = $null
        }
    }

    [pscustomobject]@{
        StatusCode = $statusCode
        Content = $content
        Json = $json
    }
}

function Start-ResponderJob {
    param(
        [int]$Port,
        [bool]$ShouldEcho
    )

    Start-Job -ScriptBlock {
        param($Port,$ShouldEcho)

        $udp = New-Object System.Net.Sockets.UdpClient($Port)
        $udp.Client.ReceiveTimeout = 1000
        $udp.Client.ReceiveBufferSize = 4194304
        $udp.Client.SendBufferSize = 4194304

        try {
            while ($true) {
                try {
                    $remote = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any,0)
                    $data = $udp.Receive([ref]$remote)

                    if ($ShouldEcho) {
                        [void]$udp.Send($data,$data.Length,$remote)
                    }
                }
                catch [System.Net.Sockets.SocketException] {
                    continue
                }
            }
        }
        finally {
            $udp.Close()
        }
    } -ArgumentList $Port,$ShouldEcho
}

function Start-RxSenderJob {
    param(
        [string]$TargetAddress,
        [int]$TargetPort,
        [int]$DurationMs,
        [int]$PayloadBytes,
        [double]$TargetMbps
    )

    Start-Job -ScriptBlock {
        param($TargetAddress,$TargetPort,$DurationMs,$PayloadBytes,$TargetMbps)

        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.SendBufferSize = 4194304
        try {
            $ip = [System.Net.IPAddress]::Parse($TargetAddress)
            $target = New-Object System.Net.IPEndPoint $ip,$TargetPort
            $payload = New-Object byte[] $PayloadBytes

            $bytesPerNs = ($TargetMbps * 1000000 / 8) / 1000000000
            $startTicks = [System.Diagnostics.Stopwatch]::GetTimestamp()
            $freq = [System.Diagnostics.Stopwatch]::Frequency
            $endTicks = $startTicks + ($DurationMs / 1000) * $freq

            [int64]$sentBytes = 0
            [int64]$sentPackets = 0
            [int64]$seq = 0

            while ([System.Diagnostics.Stopwatch]::GetTimestamp() -lt $endTicks) {
                $nowTicks = [System.Diagnostics.Stopwatch]::GetTimestamp()
                $elapsedNs = (($nowTicks - $startTicks) / $freq) * 1000000000
                $budget = [int64]($elapsedNs * $bytesPerNs) - $sentBytes

                while ($budget -ge $PayloadBytes) {
                    [byte[]]$seqBytes = [System.BitConverter]::GetBytes([int64]$seq)
                    if ([System.BitConverter]::IsLittleEndian) {
                        [Array]::Reverse($seqBytes)
                    }
                    [Array]::Copy($seqBytes,0,$payload,0,8)

                    [void]$udp.Send($payload,$payload.Length,$target)

                    $sentBytes += $PayloadBytes
                    $sentPackets++
                    $seq++
                    $budget -= $PayloadBytes
                }
            }

            [pscustomobject]@{
                sent_packets = $sentPackets
                sent_bytes = $sentBytes
            } | ConvertTo-Json -Compress
        }
        finally {
            $udp.Close()
        }
    } -ArgumentList $TargetAddress,$TargetPort,$DurationMs,$PayloadBytes,$TargetMbps
}

function Stop-RemoteTest {
    param(
        [string]$HeadsetAddress,
        [int]$HeadsetHttpPort,
        [string]$TestId
    )

    $uri = "http://$HeadsetAddress`:$HeadsetHttpPort/stop-test?test_id=$([uri]::EscapeDataString($TestId))"
    try {
        Invoke-ApiRequest -Uri $uri -TimeoutSec 3 | Out-Null
    }
    catch {
    }
}

function Stop-AllRemoteTests {
    param(
        [string]$HeadsetAddress,
        [int]$HeadsetHttpPort
    )

    $uri = "http://$HeadsetAddress`:$HeadsetHttpPort/stop-all-tests"
    try {
        Invoke-ApiRequest -Uri $uri -TimeoutSec 3 | Out-Null
        Start-Sleep -Milliseconds 500
    }
    catch {
    }
}

function Build-OutputObject {
    param(
        [Parameter(Mandatory = $true)]
        $TestState,
        [string]$HeadsetAddress
    )

    $result = $TestState.Result
    $profile = $TestState.Profile
    $output = [ordered]@{
        test_id = $TestState.TestId
        profile_name = $profile.Name
        mode = $profile.Mode
        port = $profile.Port
        headset_address = $HeadsetAddress
        status = $TestState.Status
    }

    if ($null -ne $result) {
        foreach ($prop in $result.PSObject.Properties) {
            $output[$prop.Name] = $prop.Value
        }
    }

    if ($profile.Mode -eq "rx") {
        $senderStats = $TestState.SenderStats
        if ($null -ne $senderStats) {
            $sentPackets = [int64]$senderStats.sent_packets
            $output.actual_sent_packets = $sentPackets
            $output.actual_sent_bytes = [int64]$senderStats.sent_bytes

            $receivedPackets = 0
            if ($null -ne $result -and $null -ne $result.received_packets) {
                $receivedPackets = [int64]$result.received_packets
            }

            $actualLoss = -1
            if ($sentPackets -gt 0) {
                $actualLoss = [Math]::Round((($sentPackets - $receivedPackets) * 100.0 / $sentPackets),2)
            }
            $output.actual_loss_pct = $actualLoss
        }
    }

    if ($profile.Mode -eq "throughput") {
        $output.target_mbps = if ($null -ne $output.target_mbps) { $output.target_mbps } else { $profile.TargetMbps }
    }

    [pscustomobject]$output
}

$localJobs = @()
$activeTests = @()

try {
    $profiles = @()
    for ($idx = 0; $idx -lt $TestProfiles.Count; $idx++) {
        $profiles += Normalize-TestProfile -Profile $TestProfiles[$idx] -Index $idx
    }

    if ($profiles.Count -eq 0) {
        throw "No test profiles were provided."
    }

    $duplicatePorts = $profiles | Group-Object Port | Where-Object { $_.Count -gt 1 }
    if ($duplicatePorts) {
        $ports = ($duplicatePorts | ForEach-Object { $_.Name }) -join ", "
        throw "Each test profile must use a unique UDP port per headset. Duplicate ports: $ports"
    }

    $needsResponder = @($profiles | Where-Object { $_.NeedsResponder }).Count -gt 0
    if ($needsResponder -and [string]::IsNullOrWhiteSpace($ResponderAddress)) {
        $ResponderAddress = Get-LocalIPv4
    }

    if ($needsResponder -and [string]::IsNullOrWhiteSpace($ResponderAddress)) {
        throw "ResponderAddress not provided and no IPv4 address found."
    }

    foreach ($profile in $profiles | Where-Object { $_.NeedsResponder }) {
        $job = Start-ResponderJob -Port $profile.Port -ShouldEcho ($profile.Mode -eq "rtt")
        $localJobs += $job
    }

    if ($localJobs.Count -gt 0) {
        Start-Sleep -Milliseconds 500
    }

    Stop-AllRemoteTests -HeadsetAddress $HeadsetAddress -HeadsetHttpPort $HeadsetHttpPort

    foreach ($profile in $profiles) {
        $testId = New-TestId -ProfileName $profile.Name -Mode $profile.Mode -Port $profile.Port
        $expectedPackets = $profile.ExpectedPackets
        if ($profile.Mode -eq "rx" -and $expectedPackets -lt 0) {
            $bytesPerSecond = ($profile.TargetMbps * 1000000) / 8
            $expectedPackets = [int][Math]::Floor(($bytesPerSecond * ($profile.DurationMs / 1000.0)) / $profile.PayloadBytes)
        }

        $query = [ordered]@{
            test_id = $testId
            port = $profile.Port
            duration_ms = $profile.DurationMs
            rate_hz = $profile.RateHz
            payload_bytes = $profile.PayloadBytes
            mode = $profile.Mode
            target_mbps = $profile.TargetMbps
            expected_packets = $expectedPackets
        }

        if ($profile.NeedsResponder) {
            $query.target = $ResponderAddress
        }

        $startUrl = "http://$HeadsetAddress`:$HeadsetHttpPort/start-test?$(New-QueryString -Params $query)"
        $resultUrl = "http://$HeadsetAddress`:$HeadsetHttpPort/get-results?test_id=$([uri]::EscapeDataString($testId))"

        $startResponse = Invoke-ApiRequest -Uri $startUrl -TimeoutSec 5
        if ($startResponse.StatusCode -ne 200) {
            $detail = if ($startResponse.Json -and $startResponse.Json.message) {
                [string]$startResponse.Json.message
            } elseif ($startResponse.Content) {
                $startResponse.Content
            } else {
                "HTTP $($startResponse.StatusCode)"
            }
            throw "Failed to start profile '$($profile.Name)' on ${HeadsetAddress} - $detail"
        }

        $startJson = $startResponse.Json
        $status = if ($startJson -and $startJson.status) { [string]$startJson.status } else { "RUNNING" }
        if ($status -eq "ERROR") {
            $detail = if ($startJson.message) { [string]$startJson.message } else { "start-test returned ERROR" }
            throw "Failed to start profile '$($profile.Name)' on ${HeadsetAddress} - $detail"
        }

        $activeTests += [pscustomobject]@{
            Profile = $profile
            TestId = $testId
            ResultUrl = $resultUrl
            Status = $status
            Result = $startJson
            SenderJob = $null
            SenderStats = $null
        }
    }

    foreach ($test in $activeTests | Where-Object { $_.Profile.Mode -eq "rx" }) {
        $senderJob = Start-RxSenderJob -TargetAddress $HeadsetAddress -TargetPort $test.Profile.Port `
            -DurationMs $test.Profile.DurationMs -PayloadBytes $test.Profile.PayloadBytes -TargetMbps $test.Profile.TargetMbps
        $test.SenderJob = $senderJob
        $localJobs += $senderJob
    }

    $maxDurationMs = ($profiles | Measure-Object -Property DurationMs -Maximum).Maximum
    $deadline = (Get-Date).AddMilliseconds($maxDurationMs + 20000)

    while ((@($activeTests | Where-Object { $_.Status -eq "RUNNING" }).Count -gt 0) -and ((Get-Date) -lt $deadline)) {
        Start-Sleep -Milliseconds 500

        foreach ($test in $activeTests | Where-Object { $_.Status -eq "RUNNING" }) {
            try {
                $response = Invoke-ApiRequest -Uri $test.ResultUrl -TimeoutSec 5
                if ($response.StatusCode -ne 200 -or $null -eq $response.Json) {
                    continue
                }

                $test.Result = $response.Json
                $test.Status = [string]$response.Json.status
            }
            catch {
            }
        }
    }

    foreach ($test in $activeTests | Where-Object { $_.Status -eq "RUNNING" }) {
        Stop-RemoteTest -HeadsetAddress $HeadsetAddress -HeadsetHttpPort $HeadsetHttpPort -TestId $test.TestId

        try {
            $response = Invoke-ApiRequest -Uri $test.ResultUrl -TimeoutSec 3
            if ($response.StatusCode -eq 200 -and $null -ne $response.Json) {
                $test.Result = $response.Json
                $test.Status = [string]$response.Json.status
            }
            else {
                $test.Status = "ERROR"
                $test.Result = [pscustomobject]@{
                    status = "ERROR"
                    test_id = $test.TestId
                    mode = $test.Profile.Mode
                    message = "Timed out waiting for result"
                    timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                }
            }
        }
        catch {
            $test.Status = "ERROR"
            $test.Result = [pscustomobject]@{
                status = "ERROR"
                test_id = $test.TestId
                mode = $test.Profile.Mode
                message = "Timed out waiting for result"
                timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            }
        }
    }

    foreach ($test in $activeTests | Where-Object { $null -ne $_.SenderJob }) {
        try {
            Wait-Job -Job $test.SenderJob -Timeout ([int][Math]::Ceiling(($test.Profile.DurationMs / 1000.0) + 10)) | Out-Null
            $senderOutput = Receive-Job -Job $test.SenderJob -Keep -ErrorAction SilentlyContinue
            if ($senderOutput) {
                $test.SenderStats = ($senderOutput | Select-Object -Last 1) | ConvertFrom-Json
            }
        }
        catch {
            $test.SenderStats = $null
        }
    }

    foreach ($test in $activeTests) {
        (Build-OutputObject -TestState $test -HeadsetAddress $HeadsetAddress) | ConvertTo-Json -Compress -Depth 6
    }
}
catch {
    [pscustomobject]@{
        status = "ERROR"
        mode = "script"
        headset_address = $HeadsetAddress
        message = $_.Exception.Message
        timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    } | ConvertTo-Json -Compress -Depth 4
}
finally {
    foreach ($test in $activeTests | Where-Object { $_.Status -eq "RUNNING" }) {
        Stop-RemoteTest -HeadsetAddress $HeadsetAddress -HeadsetHttpPort $HeadsetHttpPort -TestId $test.TestId
    }

    foreach ($job in $localJobs) {
        try { Stop-Job $job -Force | Out-Null } catch {}
        try { Remove-Job $job -Force | Out-Null } catch {}
    }
}
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$maxDurationMs = Get-MaxProfileDurationMs -Profiles $TestProfiles -FallbackDurationMs $TestDurationMs
$outerTimeoutSec = [int][Math]::Ceiling(($maxDurationMs / 1000.0) + 90)

"Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $SummaryLogFile -Encoding utf8
"RunCount: $RunCount" | Out-File -FilePath $SummaryLogFile -Encoding utf8 -Append
"RawLogFile: $RawLogFile" | Out-File -FilePath $SummaryLogFile -Encoding utf8 -Append
"" | Out-File -FilePath $SummaryLogFile -Encoding utf8 -Append

for ($run = 1; $run -le $RunCount; $run++) {
    Write-Host "========== Run $run / $RunCount =========="

    $jobs = @()

    try {
        for ($i = 0; $i -lt $ipList.Count; $i++) {
            $pc = $ipList[$i]
            $headIP = $headsetsIP[$i]

            $jobs += Invoke-Command -AsJob `
                -ComputerName $pc `
                -Credential $cred `
                -ScriptBlock $scriptBlock `
                -ArgumentList @(
                    $headIP,
                    $pc,
                    $HeadsetHttpPort,
                    $TestProfiles
                ) `
                -JobName ("udp-test-run{0}-{1}-{2}" -f $run,$pc,$headIP)
        }

        Wait-Job -Job $jobs -Timeout $outerTimeoutSec | Out-Null

        $results = foreach ($j in $jobs) {
            $out = Receive-Job -Job $j -Keep -ErrorAction SilentlyContinue

            [pscustomobject]@{
                Run = $run
                RunStartedAt = [DateTimeOffset]::Now.ToString("o")
                JobName = $j.Name
                Computer = $j.Location
                State = $j.State
                OutputRaw = $out
            }
        }

        $parsed = foreach ($r in $results) {
            foreach ($line in $r.OutputRaw) {
                try {
                    $obj = $line | ConvertFrom-Json

                    if ($obj.mode -eq "rtt") {
                        [pscustomobject]@{
                            run = $r.Run
                            logged_at = [DateTimeOffset]::Now.ToString("o")
                            Computer = $r.Computer
                            JobName = $r.JobName
                            State = $r.State
                            test_id = $obj.test_id
                            profile_name = $obj.profile_name
                            mode = $obj.mode
                            port = $obj.port
                            payload_bytes = $obj.payload_bytes
                            rate_hz = $obj.rate_hz
                            sent = $obj.sent
                            received = $obj.received
                            loss_pct = $obj.loss_pct
                            rtt_avg_ms = $obj.rtt_avg_ms
                            rtt_p95_ms = $obj.rtt_p95_ms
                            rtt_p99_ms = $obj.rtt_p99_ms
                            jitter_p95_ms = $obj.jitter_p95_ms
                            duration_ms = $obj.duration_ms
                            status = $obj.status
                        }
                    }
                    elseif ($obj.mode -eq "rx") {
                        [pscustomobject]@{
                            run = $r.Run
                            logged_at = [DateTimeOffset]::Now.ToString("o")
                            Computer = $r.Computer
                            JobName = $r.JobName
                            State = $r.State
                            test_id = $obj.test_id
                            profile_name = $obj.profile_name
                            mode = $obj.mode
                            port = $obj.port
                            payload_bytes = $obj.payload_bytes
                            received_mbps = $obj.received_mbps
                            received_packets = $obj.received_packets
                            expected_packets = $obj.expected_packets
                            actual_sent_packets = $obj.actual_sent_packets
                            loss_pct = $obj.loss_pct
                            actual_loss_pct = $obj.actual_loss_pct
                            duration_ms = $obj.duration_ms
                            status = $obj.status
                        }
                    }
                    elseif ($obj.mode -eq "throughput") {
                        [pscustomobject]@{
                            run = $r.Run
                            logged_at = [DateTimeOffset]::Now.ToString("o")
                            Computer = $r.Computer
                            JobName = $r.JobName
                            State = $r.State
                            test_id = $obj.test_id
                            profile_name = $obj.profile_name
                            mode = $obj.mode
                            port = $obj.port
                            payload_bytes = $obj.payload_bytes
                            target_mbps = $obj.target_mbps
                            achieved_mbps = $obj.achieved_mbps
                            sent_bytes = $obj.sent_bytes
                            duration_ms = $obj.duration_ms
                            status = $obj.status
                        }
                    }
                    else {
                        [pscustomobject]@{
                            run = $r.Run
                            logged_at = [DateTimeOffset]::Now.ToString("o")
                            Computer = $r.Computer
                            JobName = $r.JobName
                            State = $r.State
                            test_id = $obj.test_id
                            profile_name = $obj.profile_name
                            mode = $obj.mode
                            port = $obj.port
                            status = $obj.status
                            message = $obj.message
                        }
                    }
                }
                catch {
                    [pscustomobject]@{
                        run = $r.Run
                        logged_at = [DateTimeOffset]::Now.ToString("o")
                        Computer = $r.Computer
                        JobName = $r.JobName
                        State = $r.State
                        mode = "unparsed"
                        Note = [string]$line
                    }
                }
            }
        }

        foreach ($entry in $parsed) {
            ($entry | ConvertTo-Json -Compress -Depth 8) | Out-File -FilePath $RawLogFile -Encoding utf8 -Append
        }

        $rttRows = @($parsed | Where-Object mode -eq "rtt")
        $rxRows  = @($parsed | Where-Object mode -eq "rx")

        $summaryLines = @()
        $summaryLines += "Run $run completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

        foreach ($row in $rttRows) {
            $summaryLines += (
                "  RTT | Computer={0} | loss={1}% | avg={2} ms | p95={3} ms | p99={4} ms | jitter95={5} ms" -f
                $row.Computer,
                $row.loss_pct,
                $row.rtt_avg_ms,
                $row.rtt_p95_ms,
                $row.rtt_p99_ms,
                $row.jitter_p95_ms
            )
        }

        foreach ($row in $rxRows) {
            $summaryLines += (
                "  RX  | Computer={0} | mbps={1} | recv={2} | sent={3} | loss={4}% | actual_loss={5}%" -f
                $row.Computer,
                $row.received_mbps,
                $row.received_packets,
                $row.actual_sent_packets,
                $row.loss_pct,
                $row.actual_loss_pct
            )
        }

        $summaryLines += ""
        $summaryLines | Out-File -FilePath $SummaryLogFile -Encoding utf8 -Append

        $parsed | Sort-Object Computer,profile_name | Format-Table -AutoSize
    }
    finally {
        $jobs | ForEach-Object {
            try { Stop-Job $_ -Force | Out-Null } catch {}
            try { Remove-Job $_ -Force | Out-Null } catch {}
        }
    }
}

"Finished: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $SummaryLogFile -Encoding utf8 -Append
Write-Host "Raw log saved to: $RawLogFile"
Write-Host "Summary log saved to: $SummaryLogFile" 

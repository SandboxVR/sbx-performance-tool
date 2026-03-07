$siteID = '176'

# Launch 6 tests concurrently (one per PC), pairing each PC with its headset IP.
# This uses Invoke-Command -AsJob (recommended) so each remote PC runs the test in parallel.
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
# Credential
$cred = New-Object System.Management.Automation.PSCredential("SandboxVR",(New-Object System.Security.SecureString))

$scriptBlock = {
param(
    [Parameter(Mandatory = $true)]
    [string]$HeadsetAddress,
    [string]$ResponderAddress = "",
    [int]$ResponderPort = 9123,
    [int]$HeadsetHttpPort = 9124,
    [int]$DurationMs = 60000,
    [int]$RateHz = 100,
    [int]$PayloadBytes = 256,
    [ValidateSet("rtt", "throughput", "rx")]
    [string]$Mode = "rtt",
    [double]$TargetMbps = 45.0
)

function Get-LocalIPv4 {
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -notlike "169.254.*" -and
            $_.IPAddress -ne "127.0.0.1" -and
            $_.PrefixOrigin -ne "WellKnown"
        } |
        Sort-Object InterfaceMetric |
        Select-Object -First 1 -ExpandProperty IPAddress
}

$needsResponder = ($Mode -ne "rx")

if ($needsResponder -and [string]::IsNullOrWhiteSpace($ResponderAddress)) {
    $ResponderAddress = Get-LocalIPv4
}
if ($needsResponder -and [string]::IsNullOrWhiteSpace($ResponderAddress)) {
    throw "ResponderAddress not provided and no IPv4 address found."
}

$echoJob = $null
try {
    if ($needsResponder) {
        $echoJob = Start-Job -ScriptBlock {
            param($Port, $ShouldEcho)

            $udp = $null
            try {
                $udp = New-Object System.Net.Sockets.UdpClient($Port)
                $udp.Client.ReceiveTimeout = 1000
                Write-Output "Responder listening on UDP $Port"

                while ($true) {
                    try {
                        $remote = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, 0)
                        $data = $udp.Receive([ref]$remote)
                        if ($ShouldEcho) {
                            [void]$udp.Send($data, $data.Length, $remote)
                        }
                    } catch [System.Management.Automation.StopUpstreamCommandsException] {
                        break
                    } catch [System.Net.Sockets.SocketException] {
                        # timeout or socket closed; continue until stopped
                        continue
                    } catch {
                        Write-Output "Responder error: $($_.Exception.Message)"
                        break
                    }
                }
            } finally {
                if ($udp) { $udp.Close() }
            }
        } -ArgumentList $ResponderPort, ($Mode -eq "rtt")

        Start-Sleep -Milliseconds 500
    }

    $expectedPackets = -1
    if ($Mode -eq "rx" -and $PayloadBytes -gt 0 -and $TargetMbps -gt 0) {
        $bytesPerSecond = ($TargetMbps * 1000000) / 8
        $expectedPackets = [int][Math]::Floor(($bytesPerSecond * ($DurationMs / 1000.0)) / $PayloadBytes)
    }

    $startUrl = "http://$HeadsetAddress`:$HeadsetHttpPort/start-test?port=$ResponderPort&duration_ms=$DurationMs&rate_hz=$RateHz&payload_bytes=$PayloadBytes&mode=$Mode&target_mbps=$TargetMbps&expected_packets=$expectedPackets"
    if ($needsResponder) {
        $startUrl += "&target=$ResponderAddress"
    }

    $resultUrl = "http://$HeadsetAddress`:$HeadsetHttpPort/get-results"
    $stopUrl   = "http://$HeadsetAddress`:$HeadsetHttpPort/stop-test"

    Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 -Uri $startUrl | Out-Null

    if ($Mode -eq "rx") {
        $udp = New-Object System.Net.Sockets.UdpClient
        try {
            $ip = $null
            if (-not [System.Net.IPAddress]::TryParse($HeadsetAddress, [ref]$ip)) {
                $resolved = [System.Net.Dns]::GetHostAddresses($HeadsetAddress) |
                    Where-Object { $_.AddressFamily -eq "InterNetwork" } |
                    Select-Object -First 1
                if ($null -eq $resolved) {
                    throw "Failed to resolve HeadsetAddress $HeadsetAddress"
                }
                $ip = $resolved
            }

            $target  = New-Object System.Net.IPEndPoint $ip, $ResponderPort
            $payload = New-Object byte[] $PayloadBytes
            $bytesPerNs = ($TargetMbps * 1000000 / 8) / 1000000000

            $startTicks = [System.Diagnostics.Stopwatch]::GetTimestamp()
            $freq = [System.Diagnostics.Stopwatch]::Frequency
            $endTicks = $startTicks + ($DurationMs / 1000.0) * $freq

            $sentBytes = 0
            $seq = 0
            while ([System.Diagnostics.Stopwatch]::GetTimestamp() -lt $endTicks) {
                $nowTicks = [System.Diagnostics.Stopwatch]::GetTimestamp()
                $elapsedNs = (($nowTicks - $startTicks) / $freq) * 1000000000
                $budget = [int64]($elapsedNs * $bytesPerNs) - $sentBytes
                while ($budget -ge $PayloadBytes) {
                    [byte[]]$seqBytes = [System.BitConverter]::GetBytes([Int64]$seq)
                    if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($seqBytes) }
                    [Array]::Copy($seqBytes, 0, $payload, 0, [Math]::Min(8, $payload.Length))
                    [void]$udp.Send($payload, $payload.Length, $target)
                    $sentBytes += $PayloadBytes
                    $seq++
                    $budget -= $PayloadBytes
                }
            }
        } finally {
            $udp.Close()
        }
    }

    $status = "RUNNING"
    $json = $null
    $deadline = (Get-Date).AddMilliseconds($DurationMs + 15000)

    while ($status -eq "RUNNING" -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        try {
            $json = Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 -Uri $resultUrl
            $data = $json.Content | ConvertFrom-Json
            $status = $data.status
        } catch {
            # keep polling until deadline
        }
    }

    if ($status -eq "RUNNING") {
        try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Uri $stopUrl | Out-Null } catch {}
        throw "Timed out waiting for test result from $HeadsetAddress"
    }

    $json.Content
}
finally {
    if ($echoJob) {
        try { Stop-Job -Job $echoJob -Force | Out-Null } catch {}
        try { Remove-Job -Job $echoJob -Force | Out-Null } catch {}
    }
}
}

$jobs = @()
for ($i = 0; $i -lt $ipList.Count; $i++) {
    $pc     = $ipList[$i]
    $headIP = $headsetsIP[$i]

    $jobs += Invoke-Command -AsJob `
        -ComputerName $pc `
        -Credential $cred `
        -ScriptBlock $scriptBlock `
        -ArgumentList @(
            $headIP,
            $pc,
            9123,
            9124,
            300000,  # DurationMs
            100,    # RateHz
            1400,    # PayloadBytes
            "rtt",
            45.0
        ) `
        -JobName ("udp-test-{0}-{1}" -f $pc, $headIP)
}

# Do not wait forever
$null = Wait-Job -Job $jobs -Timeout 120

$results = foreach ($j in $jobs) {
    $out = Receive-Job -Job $j -Keep -ErrorAction SilentlyContinue
    [pscustomobject]@{
        JobName   = $j.Name
        Computer  = $j.Location
        State     = $j.State
        OutputRaw = $out
    }
}

$parsed = foreach ($r in $results) {
    foreach ($line in $r.OutputRaw) {
        try {
            $obj = $line | ConvertFrom-Json

            if ($obj.mode -eq "rtt") {
                [pscustomobject]@{
                    Computer       = $r.Computer
                    JobName        = $r.JobName
                    State          = $r.State
                    mode           = $obj.mode
                    payload_bytes  = $obj.payload_bytes
                    sent           = $obj.sent
                    received       = $obj.received
                    loss_pct       = $obj.loss_pct
                    rtt_avg_ms     = $obj.rtt_avg_ms
                    rtt_p95_ms     = $obj.rtt_p95_ms
                    rtt_p99_ms     = $obj.rtt_p99_ms
                    jitter_p95_ms  = $obj.jitter_p95_ms
                    duration_ms    = $obj.duration_ms
                    timestamp      = $obj.timestamp
                }
            }
            elseif ($obj.mode -eq "rx") {
                [pscustomobject]@{
                    Computer          = $r.Computer
                    JobName           = $r.JobName
                    State             = $r.State
                    mode              = $obj.mode
                    payload_bytes     = $obj.payload_bytes
                    loss_pct          = $obj.loss_pct
                    received_mbps     = $obj.received_mbps
                    received_packets  = $obj.received_packets
                    expected_packets  = $obj.expected_packets
                    duration_ms       = $obj.duration_ms
                    timestamp         = $obj.timestamp
                }
            }
            else {
                [pscustomobject]@{
                    Computer = $r.Computer
                    JobName  = $r.JobName
                    State    = $r.State
                    Note     = $line
                }
            }
        } catch {
            [pscustomobject]@{
                Computer = $r.Computer
                JobName  = $r.JobName
                State    = $r.State
                Note     = $line
            }
        }
    }
}

$parsed | Sort-Object Computer | Format-Table -AutoSize

# Cleanup outer jobs
$jobs | ForEach-Object {
    try { Stop-Job -Job $_ -Force | Out-Null } catch {}
    try { Remove-Job -Job $_ -Force | Out-Null } catch {}
}
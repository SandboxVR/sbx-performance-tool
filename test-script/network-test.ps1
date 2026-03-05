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
    [int]$DurationMs = 300000,
    [int]$RateHz = 50,
    [int]$PayloadBytes = 1400,
    [ValidateSet("rtt", "throughput", "rx")]
    [string]$Mode = "rx",
    [double]$TargetMbps = 45.0
)

function Get-LocalIPv4 {
    $ip = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" } |
        Select-Object -First 1 -ExpandProperty IPAddress
    return $ip
}

$needsResponder = ($Mode -ne "rx")
if ($needsResponder -and [string]::IsNullOrWhiteSpace($ResponderAddress)) {
    $ResponderAddress = Get-LocalIPv4
}
if ($needsResponder -and [string]::IsNullOrWhiteSpace($ResponderAddress)) {
    throw "ResponderAddress not provided and no IPv4 address found."
}

$echoJob = $null
if ($needsResponder) {
    $echoJob = Start-Job -ScriptBlock {
        param($BindAddress, $Port, $ShouldEcho)
        $endpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($BindAddress)) $Port
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.Bind($endpoint)
        try {
            while ($true) {
                $remote = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any) 0
                $data = $udp.Receive([ref]$remote)
                if ($ShouldEcho) { [void]$udp.Send($data, $data.Length, $remote) }
            }
        } finally { $udp.Close() }
    } -ArgumentList $ResponderAddress, $ResponderPort, ($Mode -eq "rtt")

    Start-Sleep -Milliseconds 250
}

$expectedPackets = -1
if ($Mode -eq "rx" -and $PayloadBytes -gt 0 -and $TargetMbps -gt 0) {
    $bytesPerSecond = ($TargetMbps * 1000000) / 8
    $expectedPackets = [int][Math]::Floor(($bytesPerSecond * ($DurationMs / 1000.0)) / $PayloadBytes)
}

$startUrl  = "http://$HeadsetAddress`:$HeadsetHttpPort/start-test?port=$ResponderPort&duration_ms=$DurationMs&rate_hz=$RateHz&payload_bytes=$PayloadBytes&mode=$Mode&target_mbps=$TargetMbps&expected_packets=$expectedPackets"
if ($needsResponder) { $startUrl += "&target=$ResponderAddress" }
$resultUrl = "http://$HeadsetAddress`:$HeadsetHttpPort/get-results"

try {
    Invoke-WebRequest -UseBasicParsing -Uri $startUrl | Out-Null
} catch {
    if ($echoJob) { Stop-Job $echoJob | Out-Null; Remove-Job $echoJob | Out-Null }
    throw
}

if ($Mode -eq "rx") {
    $udp = New-Object System.Net.Sockets.UdpClient
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($HeadsetAddress, [ref]$ip) -eq $false) {
        $resolved = [System.Net.Dns]::GetHostAddresses($HeadsetAddress) |
            Where-Object { $_.AddressFamily -eq "InterNetwork" } |
            Select-Object -First 1
        if ($null -eq $resolved) { throw "Failed to resolve HeadsetAddress $HeadsetAddress" }
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
    $udp.Close()
}

$status = "RUNNING"
$json = $null
while ($status -eq "RUNNING") {
    Start-Sleep -Seconds 1
    $json = Invoke-WebRequest -UseBasicParsing -Uri $resultUrl
    $data = $json.Content | ConvertFrom-Json
    $status = $data.status
}

if ($echoJob) { Stop-Job $echoJob | Out-Null; Remove-Job $echoJob | Out-Null }

$json.Content
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
            $headIP,        # HeadsetAddress (mandatory)
            "",             # ResponderAddress (blank; rx mode doesn't need it)
            9123,           # ResponderPort
            9124,           # HeadsetHttpPort
            1800000,        # DurationMs
            50,             # RateHz (unused in rx, but kept)
            1400,           # PayloadBytes
            "rx",           # Mode
            25.0            # TargetMbps
        ) `
        -JobName ("udp-test-{0}-{1}" -f $pc, $headIP)
}

Wait-Job -Job $jobs | Out-Null

$results = foreach ($j in $jobs) {
    $out = Receive-Job -Job $j -Keep
    [pscustomobject]@{
        JobName     = $j.Name
        Computer    = $j.Location
        OutputRaw   = $out
    }
}

$parsed = foreach ($r in $results) {
    foreach ($line in $r.OutputRaw) {
        try {
            $obj = $line | ConvertFrom-Json
            [pscustomobject]@{
                Computer          = $r.Computer
                JobName           = $r.JobName
                payload_bytes     = $obj.payload_bytes
                loss_pct          = $obj.loss_pct
                received_mbps     = $obj.received_mbps
                received_packets  = $obj.received_packets
                expected_packets  = $obj.expected_packets
                duration_ms       = $obj.duration_ms
                timestamp         = $obj.timestamp
            }
        } catch {
            [pscustomobject]@{ Computer=$r.Computer; JobName=$r.JobName; Note=$line }
        }
    }
}

$parsed | Sort-Object Computer | Format-Table -AutoSize

# Cleanup
Remove-Job -Job $jobs
 

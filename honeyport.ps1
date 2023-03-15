<#
.SYNOPSIS
    Block IP Addresses that connect to a specified port.

.DESCRIPTION
    Creates a job that listens on TCP Ports specified and when 
    a connection is established, it can either simply log or
    add a local firewall rule to block the host from further
    connections.
    Writes blocked/probed IPs to the event log named HoneyPort.

.PARAMETER  Ports
    List of Ports to listen in for connections.

.PARAMETER  WhiteList
    List of IP Addresses that should not be blocked.

.EXAMPLE
    Example monitoring on different ports
        PS C:\> .\honeyport.ps1 -Ports 70,79 -Verbose

.EXAMPLE
    Example monitoring on different ports and add whitelist of hosts
        PS C:\> .\honeyport.ps1 -Ports 4444,22,21,23 -WhiteList 192.168.10.1,192.168.10.2 -Verbose

.EXAMPLE
    Example monitoring on one port and blocking on full TCP connect
        PS C:\> .\honeyport.ps1 -Ports 21 -Block $true 

.NOTES
    Authors: John Hoyt, Carlos Perez
    Original Script Modified By: Greg Foss

    Stopping HoneyPort; 
        PS C:\> stop-job -name HoneyPort
        PS C:\> remove-job -name HoneyPort

    Listing Events;
        PS C:\> get-eventlog HoneyPort
#>

# This line enables the script to accept parameters
[CmdletBinding()]
param(
    [parameter(
    Mandatory = $true,
    ValueFromPipelineByPropertyName = $true,
    ValueFromPipeline = $true)]
    [Alias("PortNumber")]
    [int32[]]$Ports,

    [string[]]$WhiteList,

    [switch[]]$Block = $false
) 

# This function checks if the user running the script has administrative privileges
function Check-IsAdmin{
     (whoami /all | Select-String S-1-16-12288) -ne $null
}

# This function checks if the HoneyPort event log has been created and creates it if it hasn't
function Check-HoneyPortEvent
{
     if ((Get-WmiObject win32_NTEventlogfile -filter "filename='HoneyPort'") -ne $null){
         "HoneyPort Event-type has already been created!"
     } 
     else {
         new-eventlog -LogName HoneyPort -Source BlueKit
         "HoneyPort Event-type has been created!"
     }
}

# This function gets the IP addresses of the system and adds them to the whitelist
function Get-SystemIPs
{
    $NonBlockIPs = @()
    # Select only those interfaces with an IP Addresses and are up
    Get-WmiObject Win32_NetworkAdapterConfiguration  -filter "IPEnabled=True" | 
        foreach-object {
            # Get the IPAdresses on the network interfaces
            foreach ($ipAddress in $_.IPAddress){
                $NonBlockIPs += $ipAddress
            }
            # Get DNS Server IPAddresses
            foreach ($DNSsrv in $_.DNSServerSearchOrder) {
                $NonBlockIPs += $DNSsrv
            }
            # Get IPAddressed from WINS and DHCP Servers
            $NonBlockIPs += $_.WINSPrimaryServer
            $NonBlockIPs += $_.WINSSecondaryServer
            $NonBlockIPs += $_.DHCPServer
        }
    
   # Retuns a de-duplicated list
    $NonBlockIPs | select -Unique
}


# Add IPAdresses the system depends on to the list.
$WhiteList+= Get-SystemIPs

# Check if HoneyPort event type exists and create if it does not
Check-HoneyPortEvent

# Check if script is being run with administrative privileges
if (Check-IsAdmin) {

    # Loop through each port specified in the parameter
    foreach($port in $Ports) {

        # Write a message to the event log indicating that the HoneyPort is listening on the port
        $log = "HoneyPort has started listening for connections on port $port"        
        write-eventlog -logname HoneyPort -source BlueKit -eventID 1001 -entrytype Information -message $log

        # Start a background job that listens for connections on the specified port
        Start-Job -ScriptBlock {

            # Get the parameters passed to the job
            param($port, $whitelist, $Block)

            # Create objects needed for the TCP listener
            $endpoint = new-object System.Net.IPEndPoint([system.net.ipaddress]::any, $port)
            $listener = new-object System.Net.Sockets.TcpListener $endpoint

            # Run the TCP listener
            while ($True){
                $listener.start()
                $client = $listener.AcceptTcpClient() 
                $IP = $client.Client.RemoteEndPoint
                $IP = $IP.tostring()
                $IP = $IP.split(':')
                $IP = $IP[0]

                # If the IP is not on the whitelist we block it
                if ($Block -eq $true) {
                    if ($WhiteList -notcontains $IP){

                        # Write a message to the console indicating that the host has been blocked
                        write "The following host attempted to connect: $IP"

                        # Add a firewall rule to block inbound traffic from the IP
                        $firewall = New-Object -ComObject hnetcfg.fwpolicy2
                        $rule = New-Object -ComObject HNetCfg.FWRule
                        $rule.Name="Block scanner"
                        $rule.Description = "Blocking IP"
                        $rule.RemoteAddresses = $IP
                        $rule.Action = 0
                        #$rule.Direction = '1'
                        $rule.Protocol = 6
                        #$rule.RemotePorts = "*"
                        $rule.Enabled = $True
                        $firewall.Rules.Add($rule)

                        # Write a message to the event log indicating that the host has been blocked
                        $logIP = "$IP has been blocked on port $port"
                        write-eventlog -logname HoneyPort -source BlueKit -eventID 1002 -entrytype Information -message $logIP

                        # Close the TCP connection and stop the listener
                        $client.Close()
                        $listener.stop()	
                        Write "Connection closed"
                    }
                } 
                # If the IP is on the whitelist, simply log the connection
                Else {
                    $logIP = "$IP has probed the HoneyPort on port $port"
                    write-eventlog -logname HoneyPort -source BlueKit -eventID 1002 -entrytype Information -message $logIP
                    $client.Close()
                    $listener.stop()	
                    Write "Connection closed"
                }
            }
        } -ArgumentList $port,$WhiteList,$Block -Name "HoneyPort" -ErrorAction Stop
    }
} 
# If the script is not being run with administrative privileges, display an error message
else {
    Write-Error "Script needs to be run with higher privileges"
}




















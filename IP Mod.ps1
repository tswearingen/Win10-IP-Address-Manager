#Get the action to take...
function Get-Action {
  # Create prompt body
  $title = "Choose Action"
  $message = "Which action do you want to perform on $($Interface)"
  
  # Create answers
  $DHCP = New-Object System.Management.Automation.Host.ChoiceDescription "&DHCP", "Configure interface for DHCP."
  $Static = New-Object System.Management.Automation.Host.ChoiceDescription "&Static","Configure interface for static IP."
  $none = New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel", "Cancel this operation."
  
  # Create ChoiceDescription with answers
  $options = [System.Management.Automation.Host.ChoiceDescription[]]($DHCP, $Static, $none)

  # Show prompt and save user's answer to variable
  $response = $host.UI.PromptForChoice($title, $message, $options, 0)

  # Perform action based on answer
  switch ($response) {
      0 { Write-Host 'Ready to set DCHP.'; Confirm-DCHP; break } # DHCP
      1 { Write-Host 'We need more informaiton.'; Get-IPInfo; break } # Static
      2 { Write-Host 'Discarding changes and exiting...'; Start-Sleep -s 3; break } # Cancel
  }
}

#Get the static stuff from user input...
function Get-IPInfo {
  
  # Validate user entered IP address
  # ***********THIS IS WHAT WE'RE WORKING ON
    # *********** https://ridicurious.com/2018/11/14/4-ways-to-validate-ipaddress-in-powershell/ ***********
  $IPAddr = Read-Host -Prompt "Enter Enter IP Address" | Format-IPAddr ("Enter IP Address")
  $Mask = Format-IPAddr ('Enter net mask')
  $Gateway = Format-IPAddr ('Enter default gateway')
  $PriDNS = Format-IPAddr ('Enter primary DNS server address')
  $SecDNS = Format-IPAddr ('Enter secondary DNS server address')
  
  $load = ($IPAddr, $Mask, $Gateway, $PriDNS, $SecDNS)

  Confirm-Static $load
}

# Confirm the static stuff...
function Confirm-Static {
  $title = "Modify $($Interface) interface?"
  $message = "Are you sure you want to modify $($Interface) interface to Static IP with the following characteristics? IP: $($IPAddr), Net Mask: $($Mask), Gateway: $($Gateway), Primary DNS: $($PriDNS), Secondary DNS: $($SecDNS)"

  # Create answers
  $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Configure network interface."
  $modify = New-Object System.Management.Automation.Host.ChoiceDescription "&Modify information","Re-enter interface information."
  $quit = New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel", "Cancel this operation."

  # Create ChoiceDescription with answers
  $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $modify, $quit)

  # Show prompt and save user's answer to variable
  $response = $host.UI.PromptForChoice($title, $message, $options, 0)

  # Perform action based on answer
  switch ($response) {
      0 { Write-Host "Modifying $($Interface) to $($load)"; Enable-Static Start-Sleep s-3; break } # Yes
      1 { Get-IPInfo } # No
      2 { Write-Host 'Discarding changes and exiting...'; break } # Quit
  }
}

# Do the static stuff...
function Enable-Static {
  
  
  
  
# Retrieve the network adapter that you want to configure

# Remove any existing IP, gateway from our ipv4 adapter
If (($Interface | Get-NetIPConfiguration).IPv4Address.IPAddress) {
  Write-Host $Interface
  Write-Host 'Yeah yeah yeah...'; Start-Sleep -s 3; break
  #$Interface | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false
}
If (($Interface | Get-NetIPConfiguration).Ipv4DefaultGateway) {
  $Interface | Remove-NetRoute -AddressFamily $IPType -Confirm:$false
}
  
  
  
  
  break
}

# Confirm the DHCP stuff...
function Confirm-DCHP {
  $title = "Confirm"
  $message = "Change mode of $($Interface) to DHCP?"

  # Create answers
  $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Configure network interface."
  $quit = New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel", "Cancel this operation."

  # Create ChoiceDescription with answers
  $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $quit)

  # Show prompt and save user's answer to variable
  $response = $host.UI.PromptForChoice($title, $message, $options, 0)

  # Perform action based on answer
  switch ($response) {
      0 { Write-Host "Changing $($Interface) to DHCP."; Enable-DHCP; break } # Yes
      2 { Write-Host 'Discarding changes and exiting...'; break } # Quit
  }
}

# Do the DHCP stuff...
function Enable-DHCP {

  #Print the current status to the terminal
  Write-Host 'Reconfiguring $($Interface) to DHCP. Please wait.'

  # $InterfaceV4 = $Interface | Get-NetIPInterface -AddressFamily "IPv4"
  $interfaceV4 = Get-NetIPInterface -InterfaceAlias $Interface -AddressFamily IPv4
  If ($interfaceV4.Dhcp -eq "Disabled") {
    # Remove existing gateway
    ($interfaceV4 | Get-NetIPConfiguration).Ipv4DefaultGateway
    $interfaceV4 | Remove-NetRoute -Confirm:$false

    # Enable DHCP
    $interfaceV4 | Set-NetIPInterface -DHCP Enabled
    # Configure the DNS Servers automatically
    $interfaceV4 | Set-DnsClientServerAddress -ResetServerAddresses
  }
}

# Validate IP address format
function Format-IPAddr($typ) {
  $addr = Read-Host -Prompt "Enter $($typ)"
  $valid = $addr -as [IPAddress]

  if ($valid) {
    return $addr
  }
  else {
    Get-IPInfo
  }
}

# Validate IP address format
function Format-IPAddrNC($typ) {
  $addr = Read-Host -Prompt "Enter $($typ)"
  $valid = $addr -as [IPAddress]

  if ($valid) {
    return $addr
  }
  else {
    Get-IPInfo
  }
}

#This is the program entry point. Get Interface alias from user or default to Ethernet if none entered

#Attempt to re-open with elevated instance
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {  
  $arguments = "& '" +$myinvocation.mycommand.definition + "'"
  Start-Process powershell -Verb runAs -ArgumentList $arguments
  Break
}

$Interface = Read-Host -Prompt 'Enter Interface name (default is Ethernet)'
if ([string]::IsNullOrWhiteSpace($Interface))
  {
    $Interface = 'Ethernet'
  }

 Get-Action

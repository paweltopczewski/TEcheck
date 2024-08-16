###Download
# Define the URLs of the files to download
$urls = @(
    "https://www.learningcontainer.com/wp-content/uploads/2020/05/sample-zip-file.zip",
    "https://www.learningcontainer.com/wp-content/uploads/2020/05/sample-large-zip-file.zip",
    "https://file-examples.com/wp-content/uploads/2017/02/file-sample_100kB.exe",
    "https://file-examples.com/wp-content/uploads/2017/02/file-sample_500kB.exe",
    "https://file-examples.com/wp-content/uploads/2017/02/file-sample_100kB.docx",
    "https://file-examples.com/wp-content/uploads/2017/02/file-sample_500kB.docx",
    "https://www.learningcontainer.com/wp-content/uploads/2019/09/sample-pdf-file.pdf",
    "https://www.learningcontainer.com/wp-content/uploads/2019/09/sample-pdf-download-10-mb.pdf",
    "https://file-examples.com/wp-content/uploads/2017/08/file_example_PPTX_1MB.pptx",
    "https://file-examples.com/wp-content/uploads/2017/08/file_example_PPTX_5MB.pptx"
)

# Define the number of times to download each file
$downloadCount = 10

# Get the current script execution path
$downloadPath = (Get-Location).Path

# Function to download a file
function Download-File {
    param (
        [string]$url,
        [string]$path
    )
    $fileName = [System.IO.Path]::GetFileName($url)
    $destination = Join-Path -Path $path -ChildPath $fileName
    Invoke-WebRequest -Uri $url -OutFile $destination
}

# Download each file the specified number of times
foreach ($url in $urls) {
    for ($i = 1; $i -le $downloadCount; $i++) {
        Download-File -url $url -path $downloadPath
    }
}

Write-Output "Download completed."

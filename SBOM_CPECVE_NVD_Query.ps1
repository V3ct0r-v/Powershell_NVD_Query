<#
.Synopsis
   SBOM_NVD_query.ps1 - 0.98 - 10.2023 - Author: V3ct0r-v
   In the current folder uses cyclonedx file with extension .cdx.json to get cpes and query cves for each CPE, exporting to csv.
   If a previous query for a given CPE is present in the same folder, it compares the results and export a diff of the new cves detected
.EXAMPLE
   Run the Script in the same foler as a .cdx.json file
   VBA Script to add a string at the end of the CVE descriptions In Excel Alt F11 + Insert New module:

    Sub AppendToExistingOnRight()
    Dim c as range
    For each c in Selection
    If c.value <> "" Then c.value = c.value & vbNewLine & vbNewLine & "<Text you want to add at the end of the LINE>" 
    Next
    End Sub
    
#> 
Clear-Host
$version = "0.98.102023"
Write-Host("Script Version: $version") -ForegroundColor Green
Function Get-Folder($initialDirectory = "") {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.Description = "Select a folder containing your CDX files"
    $foldername.rootfolder = "MyComputer"
    $foldername.SelectedPath = $initialDirectory

    if ($foldername.ShowDialog() -eq "OK") {
        $folder += $foldername.SelectedPath
    }
    return $folder
}

$Stamp = (Get-Date).toString("yyyyMMdd_HHmmss")

# Request folder from end user
$CPEFolder = Get-Folder

if ($null -ne $CPEFolder) {

    if ( (Get-ChildItem -Path $CPEFolder -force | Where-Object Extension -in ('.json') | Measure-Object).Count -ne 0) {

        Write-Host("CycloneDX files detected!") -ForegroundColor Green

        #Set working env to folder containing the CDX files 
        Set-Location $CPEFolder

        #CISA WebRequest needed only once
        $CISAwebresponse = $null
    
        #Detect any folder containing previous results
        $DatetimeArray = @()

        foreach ($subfolder in (Get-ChildItem $CPEFolder  -Directory -Recurse )) {
            $DatetimeArray += $subfolder.Name.toString()
        }

        $DatetimeArray = $DatetimeArray -split " "
        $PreviousresultFolder = $CPEFolder + "\" + $($DatetimeArray | Sort-Object -Unique -Descending | Select-Object -First 1)

        #Create a working folder with current timestamp
        $WorkingFolder = $CPEFolder + "\NVD_CVE_Query_" + $Stamp
        New-Item -ItemType Directory -Path $WorkingFolder | Out-Null

        ## Start Logging with current timestamp
        Start-Transcript -Path "$WorkingFolder\SBOM_NVD_Query_Script_Log_$Stamp.log" -NoClobber -Force -IncludeInvocationHeader

        Write-Host("Previous Folder Result detected: $PreviousresultFolder") -ForegroundColor Green
        Write-Host("Working folder created: $WorkingFolder") -ForegroundColor Green

        Get-ChildItem -Filter *.cdx.json | 
        Foreach-Object {

            Write-Host (" ")
            Write-Host ("#######################################################################")
            Write-Host("Working on CDX File: $_") -ForegroundColor Green

            $x = Get-Content $_.FullName | ConvertFrom-Json
            $cpes = $x.components.cpe | Where-Object { $_ -ne "N/A" -and $_ -ne $null } #cpes to query

            if ($cpes -ne $null) {

                foreach ($cpe in $cpes) {
                    Write-Host (" ")
                    Write-Host ("#######################################################################")
                    #debug
                    #$cpe = "cpe:2.3:a:microsoft:edge:-:*:*:*:*:*:*:*"
                    #$cpe = "cpe:2.3:a:openssl:openssl:1.1.1l:*:*:*:*:*:*:*"
                    #$cpe = "cpe:2.3:a:microsoft:visual_studio_2019:16.8:*:*:*:*:*:*:*"
                    Write-Host ("-- CPE ID Queried: $cpe")  -ForegroundColor Cyan
                    $NVDurl = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=' + $cpe
                    $CISAurl = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
                    Write-Host ("-- URL Queried: $NVDurl")  -ForegroundColor Cyan

                    Write-Host ("-- Wait 7 sec before NVD and CISA queries...")  -ForegroundColor Cyan
                    Start-Sleep -Seconds 7

                    $proxy = ([System.Net.WebRequest]::GetSystemWebproxy()).GetProxy($NVDurl)
                    if ($proxy.port -eq 80) {
                        try {
                            $NVDwebresponse = Invoke-WebRequest $NVDurl -Proxy $proxy -UseBasicParsing | ConvertFrom-Json | Select-Object -Expand vulnerabilities | Select-Object -Expand cve
                        }
                        catch {
                            $StatusCode = [int]$_.Exception.Response.StatusCode
            
                            if ($StatusCode -eq 404) {
                                Write-Host ("-- INVALID CPE")  -ForegroundColor Red
                            }
                            elseif ($StatusCode -eq 500) {
                                Write-Host ("-- SERVER UNRESPONSIVE, DID YOU START THIS SCRIPT MULTIPLE TIMES??")  -ForegroundColor Red
                            }
                            else {
                                Write-Error "Expected 200, got $([int]$StatusCode)"
                            }
                        }

                        if ($CISAwebresponse -eq $null) {
                            $CISAwebresponse = Invoke-WebRequest $CISAurl -Proxy $proxy -UseBasicParsing | ConvertFrom-Json | Select-Object -Expand vulnerabilities | Select-Object -Expand cveID
                        }
                    }
                    else {
                        try {
                            $NVDwebresponse = Invoke-WebRequest $NVDurl -UseBasicParsing | ConvertFrom-Json | Select-Object -Expand vulnerabilities | Select-Object -Expand cve
                        }
                        catch {
                            $StatusCode = [int]$_.Exception.Response.StatusCode
            
                            if ($StatusCode -eq 404) {
                                Write-Host ("-- INVALID CPE")  -ForegroundColor Red
                            }
                            elseif ($StatusCode -eq 500) {
                                Write-Host ("-- SERVER UNRESPONSIVE, DID YOU START THIS SCRIPT MULTIPLE TIMES??")  -ForegroundColor Red
                            }
                            else {
                                Write-Error "Expected 200, got $([int]$StatusCode)"
                            }
                        }

                        if ($CISAwebresponse -eq $null) {
                            $CISAwebresponse = Invoke-WebRequest $CISAurl -UseBasicParsing | ConvertFrom-Json | Select-Object -Expand vulnerabilities | Select-Object -Expand cveID
                        }
                    }

                    if (![string]::IsNullOrEmpty($NVDwebresponse)) {
                        Write-Host ("-- Cleaning Web Responses")  -ForegroundColor Cyan

                        # Since the descriptions can be an array of 2 with 2 fields: lang(en or es)+value, we need to detect if description is an array then extract the english value at offset 0.
                        # The different values are then put into a row which is saved into a temporary array
                        # We also need to get the CVEs in their own array to be compared with the CISA database 
                        $TempArray = @()
                        $CVEArray = @()

                        foreach ($Obj in $NVDwebresponse) {
                            $TempArrayid = $Obj.id
                            #add CVE to CVE Array for CISA comparison
                            $CVEArray += $Obj.id
                            if ($Obj.descriptions.count -eq 2) {
                                $TempArraydesc = $Obj.descriptions.value[0]
                            }
                            else {
                                $TempArraydesc = $Obj.descriptions.value
                            }
                            $row = new-object PSObject -Property @{
                                col1 = $TempArrayid;
                                col2 = $TempArraydesc.Trim() -replace ('\n', ' ')
                            }
                            $TempArray += $row
                        }

                        $ObjCPEList = $TempArray | Select-Object -Property @{L = ’CVE Identifier’; E = { $_.col1 } }, @{L = 'Reason/Reference to derived Threat Events'; E = { $_.col2 } }

                        if ($displayresult) {
                            Write-Host ("-- CPE NVD Query Result:")  -ForegroundColor Yellow
                            $ObjCPEList | Format-Table -Wrap
                        }

                        #Comparing NVD CVEs to CISA
                        Write-Host ("-- Comparing NVD CVEs to CISA CVEs")  -ForegroundColor Cyan
                        $CISAresult = Compare-Object -IncludeEqual -ExcludeDifferent $CVEArray $CISAwebresponse

                        if ($CISAresult) {
                            Write-Host ("-- Matching CISA CVE detected! for $cpe :")  -ForegroundColor Magenta
                            $CISAresult | ForEach-Object {
                                Write-Host ($_.InputObject.toString()) -ForegroundColor Magenta
                            }
                        }
                        else {
                            Write-Host ("-- No Matching CISA CVEs found")  -ForegroundColor Cyan
                        }

                        # Cleanup string of special characters for querying
                        $cpe = $cpe -replace '[^a-zA-Z0-9]', ''
                        $previousresult = ''

                        $search_results = Get-ChildItem -Include *.csv –Exclude *.diff.csv -LiteralPath $PreviousresultFolder | Where-Object { ((! $_.PSIsContainer)) }
                        foreach ($file in $search_results) {
                            if ($file.Name -match $cpe) {
                                $previousresult = $file.Name
                                $oldpath = "$PreviousresultFolder\$previousresult"
                            }
                        }

                        if ($previousresult -ne '') {
                            Write-Host ("-- Previous NVD result found: $previousresult")  -ForegroundColor Yellow
                            $path = "$WorkingFolder\$cpe-$Stamp.csv"
                            Write-Host ("-- Export NVD result to $cpe-$Stamp.csv")  -ForegroundColor Cyan

                            $ObjCPEList | Export-Csv -Path $path -Force -Delimiter ',' -NoTypeInformation

                            Start-Sleep -Seconds 2

                            $newhash = Get-FileHash -Path $($path) -Algorithm SHA256
                            $oldhash = Get-FileHash -Path $($oldpath) -Algorithm SHA256

                            if ( $($newhash.Hash) -ne $($oldhash.Hash)) { 
                                $Filediff = $WorkingFolder + "\" + (Get-Item $path ).BaseName + ".diff.csv"
                                Start-Sleep -Seconds 2
                                Write-Host ("-- New NVD CVEs detected! for $cpe :")  -ForegroundColor Magenta
                                Write-Host ("") 

                                $content = @()
                                $cleanupcontent = @()

                                $content = Compare-Object (Get-Content $path) (Get-Content $oldpath) -PassThru
                    
                                #If only one line is different Compare-object returns a String instead of an object
                                if ($content.gettype().Name -ne "String") {
                                    # For each element of content, detect if a new line starts with "CVE and if no add it to the previous line (This is cleaning carriage return arrays)
                                    for ($i = 0; $i -lt $content.Length; $i++) {
                                        if ($content[$i].toString().StartsWith("`"CVE")) {
                                            $j = $i
                                        }
                                        elseif ($content[$i].toString() -ne "") {
                                            $content[$j] = $content[$j].toString() + " " + $content[$i].toString()
                                        }
                                    }

                                    # Now al the lines are built, set the rest of the content array to null
                                    if ($j -ne $content.Length) {
                                        $j = $j + 1

                                        for ($j; $j -lt $content.Length; $j++) {
                                            $content[$j] = $null
                                        }
                                    }
                                    $cleanupcontent = $content.Where({ $null -ne $_ })
                                }
                                else {
                                    $cleanupcontent = $content.Trim() -replace ('\n', ' ')
                                }
                    
                                $cleanupcontent

                                #Format the string from Compare Object to array then convert it to csv
                                $Header = @("CVE Identifier", "Reason/Reference to derived Threat Events")
                                $cvsArray = $cleanupcontent -replace '(?<Row>("[^"]*",){19})', '${Row};' -split ';'
                                $cvsObject = $cvsArray[0..($cvsArray.Count)] | ConvertFrom-Csv -Header $Header -Delimiter ','
                                $cvsObject | Export-Csv -Path $Filediff -Force -Delimiter ',' -NoTypeInformation
                    

                            }
                            else {
                                Write-Host ("-- No New NVD CVEs detected for $cpe")  -ForegroundColor Green
                            }
                        }
                        else {
                            Write-Host ("-- No Previous NVD result found")  -ForegroundColor Yellow
                            $path = "$WorkingFolder\$cpe-$Stamp.csv"
                            Write-Host ("-- Export NVD result to $cpe-$Stamp.csv...")  -ForegroundColor Cyan
                            $ObjCPEList | Export-Csv -Path $path -Force -Delimiter ',' -NoTypeInformation
                        }

                    } 
                    else {
                        Write-Host ("-- CPE NVD query did not return any CVEs")  -ForegroundColor Yellow
                    }

                }
            } 
            else {
                Write-Host("No CPEs found in the CycloneDX...") -ForegroundColor Red
            }
        }

        Write-Host("")
        Stop-Transcript

    }
    else {
        Write-Host("CycloneDX Missing! Are you sure this is the folder containing your CDX files?") -ForegroundColor Red
    }
}
else {
    Write-Host("Please select a valid Folder") -ForegroundColor Red
}


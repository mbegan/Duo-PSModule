#using the httputility from system.web
[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | out-null

[string[]]$Platf = 'unknown','google android','apple ios', `
                   'windows phone 7','rim blackberry','java j2me', `
                   'palm webos','symbian os','windows mobile', `
                   'generic smartphone'
[string[]]$Types = 'unknown','mobile','landline'
[string[]]$Capabilities = 'push','phone','sms'

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

function _numberValidator()
{
    param
    (
        [string]$number
    )
    #real validation to happen at some point...
    if ($number.Length -gt 10)
    {
        return $true
    } else {
        throw ("Too Shorty :" + $number.Length)
    }
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
    [string]$date_string = $date.ToString("ddd, dd MMM yyyy HH:mm:ss",([System.Globalization.CultureInfo]::InvariantCulture))
    [int]$offset = [System.TimeZoneInfo]::Local.BaseUtcOffset.Hours
    if ($offset -lt 0)
    {
        $offset *= -1
        [string]$zone = "-"
    } else {
        [string]$zone = "+"
    }
    $zone += $offset.ToString(([System.Globalization.CultureInfo]::InvariantCulture)).PadLeft(2,'0')
    $date_string += " " + $zone.PadRight(5,'0')
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
        Write-Verbose $canon_params
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
    Write-Verbose ("`n" + $canon)
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
    if ($result.stat -eq 'OK')
    {
        return $result.response
    } else {
        throw $result.response
    }
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
        Write-Verbose $canon_params
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

    if ($request.ContentType -ne $null)
    {
        Write-Verbose $request.ContentType
    }
 
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

function duoGetUsersAll()
{
    <# 
     .Synopsis
      Used to get all Users from a given Duo Org

     .Description
      Returns a collection of user Objects See: https://duo.com/support/documentation/adminapi#retrieve-users

     .Parameter dOrg
      string representing configured Duo Org

     .Example
      # Get all users from production duo Org
      duoGetAllUsers -dOrg prod
    #>
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$dOrg=$DuoDefaultOrg
    )

    [string]$method = "GET"
    [string]$path = "/admin/v1/users"

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

function duoGetAdminsAll()
{
    <# 
     .Synopsis
      Used to get all Users from a given Duo Org

     .Description
      Returns a collection of user Objects See: https://duo.com/support/documentation/adminapi#retrieve-users

     .Parameter dOrg
      string representing configured Duo Org

     .Example
      # Get all users from production duo Org
      duoGetAllUsers -dOrg prod
    #>
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$dOrg=$DuoDefaultOrg
    )

    [string]$method = "GET"
    [string]$path = "/admin/v1/admins"

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

function duoGetUsersbyuserName()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$userName
    )

    $parameters = @{username=$userName}
    
    [string]$method = "GET"
    [string]$path = "/admin/v1/users"
    
    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path -parameters $parameters
    }
    catch
    {
        #Write-Warning $_.TargetObject
        throw $_
    }

    return $request
}

function duoGetPhonebyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)][alias('pid','phoneid')][ValidateLength(20,20)][String]$phone_id
    )
    
    [string]$method = "GET"
    [string]$path = "/admin/v1/phones/" + $phone_id
    
    try
    {
        $request = _duoBuildCall -method $method -dOrg $dOrg -path $path
    }
    catch
    {
        #Write-Warning $_.TargetObject
        throw $_
    }

    return $request
}

function duoGetBypassForUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)][alias('uid','userid')][ValidateLength(20,20)][String]$user_id,
        [parameter(Mandatory=$false)][ValidateRange(1,10)][int]$count=1,
        [parameter(Mandatory=$false)][ValidateRange(1,10)][int]$reuse_count=2,
        [parameter(Mandatory=$false)][ValidateRange(600,86400)][int]$valid_secs=3600
    )

    $parameters = @{
                    username    = $userName
                    count       = $count
                    valid_secs  = $valid_secs
                    reuse_count = $reuse_count
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

function duoCreatePhone()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$dOrg=$DuoDefaultOrg,
        [Validatescript({_numberValidator -number $_})][string]$number,
        [string]$name,
        [string]$extension,
        [Validatescript({if ($Types.Contains($_.ToLower())) { $true } else { throw $Types }})][string]$type,
        [Validatescript({if ($Platf.Contains($_.ToLower())) { $true } else { throw $Platf }})][string]$platform,
        [string]$predelay,
        [string]$postdelay
    )
    [string[]]$param = "number","name","extension","type","platform","predelay","postdelay"

    $parameters = New-Object System.Collections.Hashtable

    foreach ($p in $param)
    {
        if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
        {
            $parameters.Add($p,$(Get-Variable -Name $p -ValueOnly))
        }
    }
    
    [string]$method = "POST"
    [string]$path = "/admin/v1/phones"

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

function duoCreateActivationCode()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)][alias('pid','phoneid')][ValidateLength(20,20)][String]$phone_id,
        [parameter(Mandatory=$false)][ValidateRange(1,86400)][int]$valid_secs=3600,
        [parameter(Mandatory=$false)][ValidateSet("0","1")][string]$install
    )
    
    [string[]]$param = "valid_secs","install"

    $parameters = New-Object System.Collections.Hashtable

    foreach ($p in $param)
    {
        if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
        {
            $parameters.Add($p,$(Get-Variable -Name $p -ValueOnly))
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

function duoAssocPhoneToUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)][alias('uid','userid')][ValidateLength(20,20)][String]$user_id,
        [parameter(Mandatory=$true)][alias('pid','phoneid')][ValidateLength(20,20)][String]$phone_id
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

Export-ModuleMember -Function duo* -Alias duo*
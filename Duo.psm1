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

function _numberNormalize()
{
    param
    (
        [string]$number
    )

    if ($number -ne $null)
    {
        $newPhone = "+" + $number.Replace("P","").Replace("+","").Replace(" ","").Replace("-","").Replace("(","").Replace(")","").Trim().ToString()
    } else {
        $newPhone = ""
    }

    return $newPhone
}

function _numberValidator()
{
    param
    (
        [string]$number
    )

    $number = _numberNormalize -number $number

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
            [String]$username
    )

    [string[]]$param = "username"
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

function duoGetUserBypass()
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
            [ValidateRange(1,10)]
            [int]$reuse_count=2,
        [parameter(Mandatory=$false)]
            [ValidateRange(600,86400)]
            [int]$valid_secs=3600
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
            [String]$admin_id
    )

    [string]$method = "GET"
    [string]$path = "/admin/v1/admins"

    if ($admin_id)
    {
        $path += "/" + $admin_id
    }

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

function duoCreateAdmin()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [Validatescript({_emailValidator -email $_})]
            [string]$email,
        [parameter(Mandatory=$false)]
            [ValidateLength(8,254)]
            [string]$password=(_newPassword -Length 10),
        [parameter(Mandatory=$true)]
            [ValidateLength(1,100)]
            [string]$name,
        [parameter(Mandatory=$true)]
            [Validatescript({_numberValidator -number $_})]
            [string]$phone,
        [parameter(Mandatory=$false)]
            [ValidateSet('Owner','Administrator','Integration Manager',`
                         'User Manager','Help Desk','Billing','Read-only' )]
            [string]$role='Read-only'
    )

    if ($phone)
    {
        $phone = _numberNormalize -number $phone
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
    [string]$path = "/admin/v1/admins"

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

function duoModifyAdmin()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$dOrg=$DuoDefaultOrg,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [alias('aid','adminid')]
            [String]$admin_id,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [string]$name,
        [parameter(Mandatory=$false)]
            [Validatescript({_numberValidator -number $_})]
            [string]$phone,
        [parameter(Mandatory=$false)]
            [ValidateLength(8,254)]
            [string]$password,
        [parameter(Mandatory=$false)]
            [ValidateSet('Owner','Administrator','Integration Manager',`
                         'User Manager','Help Desk','Billing','Read-only' )]
            [string]$role
    )

    if ($phone)
    {
        $phone = _numberNormalize -number $phone
    }
    
    [string[]]$param = "name","phone","password","role"

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
    [string]$path = "/admin/v1/admins/" + $admin_id

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
            [string]$extension
    )
    [string[]]$param = "number","extension"
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
        $number = _numberNormalize -number $number
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

     .Example
      # Get all users from "prod" duo Org
      duoGetToken -dOrg prod

     .Example
      # Get specific token from default duo Org
      duoGetToken -token_id prod

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
            [string]$serial
    )

    [string[]]$param = "type","serial"
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
        $number = _numberNormalize -number $number
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

Export-ModuleMember -Function duo* -Alias duo*
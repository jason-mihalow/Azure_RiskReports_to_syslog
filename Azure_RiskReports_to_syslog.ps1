<#
Script written by Jason Mihalow 

Description:  This script will query for $querytime amount of time from the Microsoft Graph Beta API and retrieve the 6 available Azure identity risk reports.  These reports are detailed here: https://developer.microsoft.com/en-us/graph/docs/api-reference/beta/resources/identityriskevent.  The script will write the log id values to a file so that they can be compared during the next execution of the script.  This will ensure that if there is a delay in the creation of the risk report alerts due to an issue on the Azure side, we won't miss any logs.  The script will get the risk reports and send any new logs when compared to the previous execution.  The new logs will be sent via TCP to give the most space for log text.  The six risk report types are:

leakedCredentialsRiskEvents
anonymousIpRiskEvents
malwareRiskEvents
suspiciousIpRiskEvents
unfamiliarLocationRiskEvents
impossibleTravelRiskEvents

Variables that need to be configured:
$ClientID
$ClientSecret
$tenantdomain
$dstserver
$dstport

Schedule this script to execute using the local task scheduler.  You will want to tune the frequency at which the script is executed.  The time it takes to execute one run should not be longer than the execution frequency.  The time it takes to execute the script one time will vary depending on the amount of risk alerts you have in your portal.  You can adjust $querytime to impact the amount of time one execution of the script takes.  Less $querytime = less ids to compare = shorter execution
#>


#set all the variables needed to gain an Oauth2 token
$ClientID       = ""        # Should be a ~36 hex character string; insert your info here
$ClientSecret   = ""    # Should be a ~44 character string; insert your info here
$tenantdomain   = ""    # For example, contoso.onmicrosoft.com
$loginURL       = "https://login.microsoft.com"
$resource       = "https://graph.microsoft.com"

#Get Oauth2 token
$body       = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
$oauth      = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body

#destination syslog server
$dstserver = ""

#destination TCP port
$dstport = ""

#create TCP socket connection using .NET
$tcpConnection = New-Object System.Net.Sockets.TcpClient($dstserver, $dstport)
$tcpStream = $tcpConnection.GetStream()
$writer = New-Object System.IO.StreamWriter($tcpStream)
$writer.AutoFlush = $true

#set the amount of time you want to process; make sure it is in universal time
$querytime = (get-date).AddDays(-2)
$querytime = $querytime.ToUniversalTime()

#format querytime for use in the API call
$querytime = "{0:s}" -f $querytime + "Z"

#if we successfully got an Oauth2 token
if ($oauth.access_token -ne $null) 
{
    #set header parameters for API query
    $headerParams = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}
    
    #create an array of the various reports we can pull   
    $links = @("https://graph.microsoft.com/beta/leakedCredentialsRiskEvents","https://graph.microsoft.com/beta/anonymousIpRiskEvents","https://graph.microsoft.com/beta/malwareRiskEvents","https://graph.microsoft.com/beta/suspiciousIpRiskEvents","https://graph.microsoft.com/beta/unfamiliarLocationRiskEvents","https://graph.microsoft.com/beta/impossibleTravelRiskEvents")
    
	#initialize array
    $lastrun_ids = @()
	
	#get the current path
	$current_path = convert-path .

	#location of file of ids
	$test_path = $current_path + "\current_report_ids.txt"

    if ($test_path)
    {
        #read the list of ids in from the previous execution
        $lastrun_ids = Get-Content $test_path

        #delete the existing last run file of ids 
        remove-item -Path $test_path
    }
    
    foreach($url in $links)
    {

        #set the error flag to makes sure we only proceed when we have positive results
        $errorflag = $true

        #set the url to be queried
        #query the API for the first page of results
        $url = $url + "?`&filter=riskEventDateTime ge $querytime"

        #do this while $errorflag = true
        do
        {
            #do this while we don't have results
            do
            {
                #use try block to avoid any error crashing the script
                try
                {
                    #get first page of results 
                    $myReport = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url)
                    
                    #if we didn't get an error then set $errorflag = false so we can exit loop
                    $errorflag = $false
                }
                #catch the error; most likely will be too many queries; wait 5 seconds and then try again
                catch 
                {
                    $error
                    $writer.writeline($error)
                    start-sleep -s 5
                }

            }while($errorflag -eq $true)
            
            #if there are ids from the last execution; find unique ids and send to SIEM
            if ($lastrun_ids)
            {
                #for each $event in the 'Content' section of the API results
                foreach ($event in ($myReport.Content | ConvertFrom-Json).value)
                {
                    
                    #send the event id to the new ids file
                    $event.id | Out-File -Append -NoClobber -FilePath $test_path
                        
                    #test if the current id is in the list of ids from the previous execution
                    $current_id = $event.id
                    $unique = $lastrun_ids -notcontains "$current_id"
                   
                    #if the event was not in the list from the previous execution
                    if ($unique)
                    {
                        #assign $line to the compressed json
                        $line = ($event | Convertto-Json -Compress)

                        #send $line to the SIEM view TCP
                        $writer.Writeline($line)
                    }
                }
             }
             #no ids from last execution; send all events to SIEM
             else
             {
                #for each $event in the 'Content' section of the API results
                foreach ($event in ($myReport.Content | ConvertFrom-Json).value)
                {
                 
                    #send the event id to the new ids file
                    $event.id | Out-File -Append -NoClobber -FilePath $test_path
                
                    #assign $line to the compressed json
                    $line = ($event | Convertto-Json -Compress)

                    #send $line to the SIEM view TCP
                    $writer.Writeline($line)
                }
             }
                
        #update the url value to the next page of results
        $url = ($myReport.Content | ConvertFrom-Json).'@odata.nextLink'

        #while there is another page of results              
        }while($url -ne $null)
    }

#clean up
$writer.close
$tcpConnection.Close()
}

#we did not get an Oauth2 token; send alert
else 
{
    #let SIEM know we are having issues with the API authentication
    $line = "WARNING: API authentication issue.  We were unable to obtain an OAUTH token.  Check API key validity."
    $writer.WriteLine($line)   
} 

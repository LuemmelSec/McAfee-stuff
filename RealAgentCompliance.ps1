#Script for defining a real agent-compliance in McAfee ePO
#LuemmelSec
#
#--------------------------------------------------------------------
#Declaration of variables

#Make Changes here
$Tag = "NonCompliantAgent"
$creds = Get-Credential -Message "Please enter ePO-Credentials"
$adcreds = Get-Credential -Message "Please enter AD-Credentials for LDAP-Queries Domain\User"
$Uri = "https://192.168.1.1:8443/remote/system.applyTag?"
$epocsvpath = "C:\reports\agent_compliance.csv"
$Culture = New-Object System.Globalization.CultureInfo("de-DE")

#Do not changes these
$ExportAdCsvName = "adexport.csv"
$ImportEpoCsvName = "epoimport.csv"
$ExportResultsCsvName = "Results.csv"
$NonCompliantSystemsCsvName = "NonCompliantSystems.csv"
$compare = ""
$missmatch = ""

#---------------------------------------------------------------------

#Load AD-Module if not existent by default ie. Windows Server 2008
Import-Module activedirectory

#Read all Computers from AD, Change Colum-Name from Name -> Systemname, format LastLogon-Time to readable format and export to CSV
Get-ADComputer -credential $adcreds -Filter * -Properties * | Select-Object @{Name='Systemname';Expression='Name'}, @{Name="LastLogon";Expression={([datetime]::FromFileTime($_.LastLogon).ToString("dd.MM.yy"))}} | export-csv "$ExportAdCsvName" –NoTypeInformation


#Import ePO-CSV for later comparison. If Value is empty we set 01.01.01
Import-Csv $epocsvpath | ForEach-Object {
    if (!$_.'Letzte Kommunikation') {$_.'Letzte Kommunikation' = "01.01.01"}
    else {$_.'Letzte Kommunikation' = $_.'Letzte Kommunikation'.Substring(0,8)}
$_} | Sort SystemName | Export-Csv .\"$ImportEpoCsvName" –NoTypeInformation


#Set ePO-CSV as Master and compare all finding from AD-CSV if they also exist in the ePO-CSV. Create a list with all matches and contain Systemname, LastLogon from AD and LastCommunication from ePO for each record -> export to csv
$computers = Import-CSV -Path .\"$ImportEpoCsvName" | Group-Object -AsHashTable -AsString -Property Systemname
$compare = Import-Csv -Path .\"$ExportAdCsvName" | foreach {
    $key = $PSItem.Systemname
    if ($key -in $computers.Keys)
    {
        [PSCustomObject]@{
            Systemname = $key
            ePOCom = [datetime]::ParseExact($computers[$key].'Letzte Kommunikation', "dd.MM.yy", $Culture)
            ADCom = [datetime]::ParseExact($PSItem.LastLogon, "dd.MM.yy", $Culture)
        }
    }
}
$compare | Sort SystemName | Export-Csv -Path .\"$ExportResultsCsvName" -NoTypeInformation -Encoding ASCII

#Remove all Systems that are compliant so we only see systems with a missmatch
$import = import-csv .\"$ExportResultsCsvName"
$missmatch = foreach ($i in $import) { 
      if ((get-date $i.adcom) -gt (get-date $i.epocom)) {
          [PSCustomObject]@{
            Systemname = $i.Systemname
            ePOCom = $i.ePOCom
            ADCom = $i.ADCom
            }
          }
      }
$missmatch | Sort SystemName | Export-Csv -Path .\"$NonCompliantSystemsCsvName" -NoTypeInformation -Encoding ASCII

#Remove unneeded Items
Remove-Item .\"$ExportAdCsvName"
Remove-Item .\"$ImportEpoCsvName"
Remove-item .\"$ExportResultsCsvName"

#---------------------------------------------------

#Tagging-Part

#Enforce PowerShell to use TLS 1.2 instead of 1.0 to allow communication with ePO
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#--------------------------------------------------

#Magic-part for ignoring Self-Signed-Cert Errors. We can exlude this part if we import both the Orion-Root-Cert and the Other-Person-Cert from the ePO into the Computer we run the script from
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

#--------------------------------------------------

#Here we make the needed API-Calls to set the TAG to noncompliant systems using ePO Web-API
$noncompliant = import-csv .\"$NonCompliantSystemsCsvName"
foreach ($n in $noncompliant) {
    $completeuri = $uri + "names=" + $n.systemname + "&tagName=" + $Tag
    Invoke-RestMethod -Uri $completeuri -Credential $creds
   }

#Delete the last file
Remove-item .\"$NonCompliantSystemsCsvName"
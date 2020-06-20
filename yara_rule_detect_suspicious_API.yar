import "pe"

rule Malicious_Api {

    meta:
        description = "YARA Rule That Can Find Improperly Signed Executables"
        author = "sonumandal"
        date = "2020-06-20"
        reference = "https://www.winitor.com/"
        //This Rule can also detect False positive you can tune the condition as per your need 

   strings:
       $name1 = "EnumerateLocalComputerNames"    // Kernel32.dll    
       $name2 = "GetVDMCurrentDirectories"
       $name3 = "GetProcessIdOfThread"
       $name4 = "SetThreadPriorityBoost"
       $name5 = "GetNamedPipeClientProcessId"
       $name6 = "LocalShrink"
       $name7 = "GetSystemRegistryQuota"
       $name8 = "SetProcessPriorityBoost"
       $name9 = "GetSystemWindowsDirectory"
       $name10 = "LoadLibraryA"

       $name11 = "connect"                            // wsock32.dll  
       $name12 = "getpeername"
       $name13 = "getsockname"
       $name14 = "getsockopt"
       $name15 = "ioctlsocket"
       $name16 = "listen"
       $name17 = "setsockopt"
       $name18 = "send"
       $name19 = "recv"
       $name20 = "sendto"

       $name21 = "HttpSendRequest"                    // wininet.dll
       $name22 = "HttpSendRequestEx"
       $name23 = "InternetCrackUrl"
       $name24 = "InternetCrackUrl"
       $name25 = "InternetOpen"
       $name26 = "InternetConnect"
       $name27 = "CommitUrlCacheEntry"
       $name28 = "InternetAutodial"
       $name29 = "DeleteUrlCacheEntry"
       $name30 = "ResumeSuspendedDownload"
      
       $name31 = "DsListSites"                        // ntdsapi.dll
       $name32 = "DsFreePasswordCredentials"
       $name33 = "DsFreeNameResult"
       $name34 = "DsUnBind"
       $name35 = "DsBind"
       $name36 = "DsMapSchemaGuids"
       $name37 = "DsCrackSpn"
       $name38 = "DsFreeDomainControllerInfo"
       $name39 = "DsMakeSpn"
       $name40 = "DsGetDomainControllerInfo"

       $name41 = "EncryptMessage"                     // secur32.dll
       $name42 = "DecryptMessage"
       $name43 = "stQuerySecurityPackageInforing"
       $name44 = "LsaLookupAuthenticationPackage"
       $name45 = "LsaDeregisterLogonProcess"
       $name46 = "LsaConnectUntrusted"
       $name47 = "LsaFreeReturnBuffer"
       $name48 = "GetUserNameEx"
       $name49 = "DeleteSecurityContext"
       $name50 = "VerifySignature"
      

    condition:

    uint16(0) == 0x5A4D 
    and any of ($name*) 
       
}            

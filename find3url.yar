rule URL_binary   // this rule can be helpful when it comes to detect malacious C2 channels 
{
    meta:
        description = "THIS RULE CAN FIND BINARIES THAT HAVE MORE THAN 3 URLS"
        author = "read_write_execute"
        date = "2020-06-03"

    strings:
        $a = "http" fullword ascii  wide 
        $b = "https" fullword ascii wide 
    
    condition:
        uint16(0) == 0x5a4d               // this means executables  
        and ( #a + #b ) >= 3             // sometime we need to know how specific a string is prsnt in the memory for tht we use # sign 

    
}

rule wanna_cry_process_detection    
{     //this rule is a example how a professional yara rule looks like 
     // Professionally documented rule can help other users to implement the rule easily 
    meta:
        Ver = "1.0"
        Date = "2020-06-03"
        Author = "sonumadnal" 
        E-Mail = "wannacry@gmail.com"    //example email address 
        Refrence = "https://bit.ly/3dEqotL"
        Hash = "84c82835a5d21bbcf75a61706d8ab549"
        Description = "This rule will going to detect wannacry ransomware"  



    strings:
        $a = "db349b97c37d22f5ea1d1841e3c89eb4" 
        $b = "f351e1fcca0c4ea05fc44d15a17f8b36" 
    
    condition:
        uint16(0) == 0x5a4d  // this means executables  
        and ( a + b )            
   
}
import "pe"

rule find_chinese_executables { 

      /*
         This Yara rule can find chinese Executables with the help of 
         Language Identifier Constants and Strings
     */

    meta:
        description = "YARA Rule That Can Find Chinese Executables"
        author = "sonumandal"
        date = "2020-06-10"
        reference = "https://bit.ly/2XNA3cc" 

    condition:

       uint16(0) == 0x5A4D   //this mz header of a exe always starts from 5A4D in hex aka magic bytes 
       and filesize < 100KB 
       and  pe.version_info["CompanyName"] contains "Microsoft"
       and  pe.number_of_signatures > 0
       and not for all i in (0..pe.number_of_signatures - 1 ):
        (
            pe.signatures[i].issuer contains "Microsoft" or 
            pe.signatures[i].issuer contains "VeriSign" 
            //sometimes adverseries singn there exe with VeriSign
        ) 
        
       or pe.language(0x0004)  //Chinese (Simplified)
       or pe.language(0x7804)  //Chinese (Simplified)
       or pe.language(0x0804)  //People's Republic of China
       or pe.language(0x7C04)  //Singapore
       or pe.language(0x0C04)  //Hong Kong S.A.R.
       or pe.language(0x1404)  //Macao S.A.R.
       or pe.language(0x0404)  //Taiwan
        
}

      

          

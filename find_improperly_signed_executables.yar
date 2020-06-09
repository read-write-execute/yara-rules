import "pe"

rule fake_signed_MS_metainfo {

    meta:
        description = "YARA Rule That Can Find Improperly Signed Executables"
        author = "sonumandal"
        date = "2020-06-08"
        reference = "https://bit.ly/2MIcxXz"

    condition:

       uint16(0) == 0x5A4D 
       and filesize < 1000000
       and  pe.version_info["CompanyName"] contains "Microsoft"
       and  pe.number_of_signatures > 0
       and not for all i in (0..pe.number_of_signatures - 1 ):
        (
            pe.signatures[i].issuer contains "Microsoft" or 
            pe.signatures[i].issuer contains "VeriSign" 
        )
          
}

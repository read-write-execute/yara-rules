import "pe"

rule  find_small_portable_exe_less_then_500KB {

    meta:
        Description = "A YARA Rule That Can Find Small Portable Executables"
        Author = "sonumandal"
        Date = "2020-06-09"
        Version = "1.0" 

    condition:

       uint16(0) == 0x5A4D  //this means it should be an executable (mz header of a PE valued 5A4D in hex )
       and filesize > 500000  //yara rule file system read data in byte . here 500000 means 500KB of data  
       
}   
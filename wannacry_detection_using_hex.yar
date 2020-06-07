rule wannacry_detection_using_hex_wildcard 
{
    meta:
        description = "Rule That Searches For Strings Using Hex And Wild-Cards"
        author = "sonumandal"
        date = "2020-06-07"
        reference = "https://bit.ly/3dEqotL"
        hash = "84C82835A5D21BBCF75A61706D8AB549"
    
    strings:
       $hex_string = { 56 33 F6 39 74 [1-10] E0 40 00 EB }

    condition:
       $hex_string
}

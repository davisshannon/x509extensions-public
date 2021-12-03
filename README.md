IMPHASH
=================================

This Zeek package calculates the "imphash" and populates pe.log with a new field `imphash`. Optionally, a vector `imphash_vector` can be logged in pe.log.  

For an overview of imphash refer to https://www.mandiant.com/resources/tracking-malware-import-hashing  

# Requirements  
  - Spicy https://github.com/zeek/spicy   
  - Spicy plugin https://github.com/zeek/spicy-plugin  
  - The portable executable Spicy analyzer https://github.com/zeek/spicy-analyzers/  


# Example output 
```
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   pe
#open   2021-11-18-14-16-55
#fields ts      id      machine compile_ts      os      subsystem       is_exe  is_64bit        uses_aslr       uses_dep        uses_code_integrity     uses_seh        has_import_table        has_export_table        has_cert_table  has_debug_data  section_names   imphash
#types  time    string  string  time    string  string  bool    bool    bool    bool    bool    bool    bool    bool    bool    bool    vector[string]  string
1637181420.050549       Fx5oCv4wPw7qkyY1V8      I386    1612478773.000000       Windows XP      WINDOWS_GUI     T       F       T       T       F       T       T       T       T       T       .text,.rdata,.data,.rsrc,.reloc 843a657ffd3cb839eed7659a80a978af
#close  2021-11-18-14-16-55
```

# Credits:
Shannon Davis @splunk  
Ben Reardon   @corelight  

module IMPHASH;

@load base/files/pe
@load spicy-analyzers/pe

redef record PE::Info += {
    imphash_vector: vector of string &optional &log;
    imphash: string &optional &log;
};

const extensions: pattern = /\.dll$/i | /\.sys$/i | /\.ocx$/i;
const winsock_dll_patterns: pattern = /^ws2_32$/i | /^wsock32$/i ;

event pe_import_table(f: fa_file, it: PE::ImportTable) 
    {
    f$pe$imphash_vector = vector();
    for (i in it$entries)
        {
        local entry = it$entries[i];
        
        if (extensions !in entry$dll)
            next;
        
        local dll_stripped = to_lower(split_string1(entry$dll, /\./ )[0]);
        
        for (j in entry$imports)
            {
            local import = entry$imports[j];
            if (import?$name)
                {
                f$pe$imphash_vector += dll_stripped + "." + to_lower(import$name);
                next;
                }
        
            if (dll_stripped == "oleaut32")
                {
                f$pe$imphash_vector += dll_stripped + "." + oleaut32[import$ordinal];
                next;
                }

            if (winsock_dll_patterns in dll_stripped)
                {
                f$pe$imphash_vector += dll_stripped + "." + ws2_32[import$ordinal];
                next;
                }
            # Catch all for dlls that use ordinals and are not in the dictionary
            if (!import?$name)
                {
                f$pe$imphash_vector += dll_stripped + "." + fmt("ord%s",import$ordinal);
                next;
                }
            }
        }
    f$pe$imphash = md5_hash(join_string_vec(f$pe$imphash_vector,","));
    }


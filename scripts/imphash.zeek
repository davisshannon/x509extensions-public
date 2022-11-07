module X509Extensions;
  
@load base/files/x509

export {

  redef enum Log::ID += { LOG };

  type Info: record {
    ## Name of extension
    name: string &log;
    ## Short name of extension
    short_name: string &log;
    ## OID value of extension
    oid: string &log;
    ## Is the extension critical
    critical: bool &log;
    ## Value of extension
    value: string &log;
    fingerprint: string &log;
  };

}

event zeek_init() {
  Log::create_stream(LOG, [$columns=Info, $path="x509_extensions"]);
}

event x509_extension(f: fa_file, ext: X509::Extension) {
  if ( f$info?$x509 ) {
    {
    f$info$x509$extensions += ext;

    Log::write(LOG, Info($name=ext$name,
                         $short_name=ext$short_name,
                         $oid=ext$oid,
                         $critical=ext$critical,
                         $value=ext$value,
                         $fingerprint=f$info$x509$fingerprint));
    }
  }
}

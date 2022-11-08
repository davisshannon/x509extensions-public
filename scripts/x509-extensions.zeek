module X509Extensions;
  
@load base/files/x509

export {

  redef enum Log::ID += { LOG };

  type Info: record {
    ## Current timestamp.
    ts: time &optional &log;
    ## Name of extension
    name: string &optional &log;
    ## Short name of extension
    short_name: string &log;
    ## OID value of extension
    oid: string &optional &log;
    ## Is the extension critical
    critical: bool &log;
    ## Value of extension
    value: string &optional &log;
    ## X509 Fingerprint
    fingerprint: string &log;
    ## Unique ID for the connection
    uid: string &optional &log;
  };

}

event zeek_init() {
  Log::create_stream(LOG, [$columns=Info, $path="x509_extensions"]);
}

event x509_extension(f: fa_file, ext: X509::Extension) {


  if ( f$info?$x509 ) {
    {
      for ( [cid], c in f$conns )
        {
        Log::write(LOG, Info($name=ext$name,
                             $short_name=ext$short_name,
                             $oid=ext$oid,
                             $critical=ext$critical,
                             $value=ext$value,
                             $fingerprint=f$info$x509$fingerprint,
                             $ts=network_time(),
                             $uid=c$uid));
      }
    }
  }
}

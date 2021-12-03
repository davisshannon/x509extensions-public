# @TEST-EXEC: zeek -r $TRACES/petest.pcap $PACKAGE %INPUT 
# @TEST-EXEC: cat pe.log | zeek-cut imphash > pe_imphash_petest.log
# @TEST-EXEC: btest-diff pe_imphash_petest.log

# @TEST-EXEC: zeek -r $TRACES/steam.pcap $PACKAGE %INPUT
# @TEST-EXEC: cat pe.log | zeek-cut imphash > pe_imphash_steam.log
# @TEST-EXEC: btest-diff pe_imphash_steam.log


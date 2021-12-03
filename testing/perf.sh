rm *.log
hyperfine --runs 3 'zeek -Cr Traces/pe_300.pcap' 'zeek -Cr Traces/pe_300.pcap ../scripts/__load__.zeek'
rm *.log


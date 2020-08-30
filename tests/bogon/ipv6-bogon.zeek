#
# @TEST-EXEC: zeek -C -r $TRACES/ipv6-bogon.pcap ../../../scripts/bogon %INPUT
# @TEST-EXEC: btest-diff conn.log

# This test won't flag all hosts as bogon

# No private network flagging
redef Bogon::private_as_bogon = F;
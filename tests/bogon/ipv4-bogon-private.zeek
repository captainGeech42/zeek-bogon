#
# @TEST-EXEC: zeek -C -r $TRACES/ipv4-bogon.pcapng ../../../scripts/bogon %INPUT
# @TEST-EXEC: btest-diff conn.log

# This test will flag orig & resp on all 5 conns

# Yes private network flagging
redef Bogon::private_as_bogon = T;
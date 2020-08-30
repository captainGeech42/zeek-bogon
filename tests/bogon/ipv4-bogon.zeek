#
# @TEST-EXEC: zeek -C -r $TRACES/ipv4-bogon.pcapng ../../../scripts/bogon %INPUT
# @TEST-EXEC: btest-diff conn.log

# This test will flag resp on all 5 conns

# No private network flagging
redef Bogon::private_as_bogon = F;
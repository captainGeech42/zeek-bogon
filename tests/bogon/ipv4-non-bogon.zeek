#
# @TEST-EXEC: zeek -C -r $TRACES/ipv4-non-bogon.pcapng ../../../scripts/bogon %INPUT
# @TEST-EXEC: btest-diff conn.log

# This test won't flag any hosts as bogon

# No private network flagging
redef Bogon::private_as_bogon = F;
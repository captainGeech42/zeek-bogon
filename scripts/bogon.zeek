##! Add bogon_orig and bogon_resp fields to the conn log to show if an IP is
##! in a bogon range

module Bogon;

export {
    redef record Conn::Info += {
        bogon_orig: bool &optional &log;
        bogon_resp: bool &optional &log;
    };

    # If you want to mark RFC 1918/4193 IP space as bogon, set this to T
    const private_as_bogon = F &redef;
}

global bogon_networks: set[subnet] = {
    0.0.0.0/8,
    127.0.0.0/8,
    169.254.0.0/16,
    192.0.2.0/24,
    198.51.100.0/24,
    203.0.113.0/24,
    224.0.0.0/4,
    255.255.255.255/32,
    [::1]/128,
    [100::]/64,
    [2001:db8::]/32,
    [fe80::]/10,
    [ff00::]/8
};

global private_networks: set[subnet] = {
    10.0.0.0/8,
    172.16.0.0/12,
    192.168.0.0/16,
    [fc00::]/7
};

function mark_as_bogon(ip: addr): bool
    {
    # check the bogon networks
    for ( net in bogon_networks )
        {
        if ( ip in net )
            return T;
        }
    
    if ( private_as_bogon )
        {
        # need to check private networks (default no)
        for ( net in private_networks )
            {
            if ( ip in net )
                return T;
            }
        }

    # IP isn't bogon
    return F;
    }

event connection_state_remove(c: connection)
    {
    # Set the bogon field for orig and resp hosts
    c$conn$bogon_orig = mark_as_bogon(c$id$orig_h);
    c$conn$bogon_resp = mark_as_bogon(c$id$resp_h);
    }
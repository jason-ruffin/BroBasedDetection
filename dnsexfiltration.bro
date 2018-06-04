module Foo;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts: time        &log;
        uid: string     &log;
        id: conn_id     &log;
        dns: DNS::Info  &log &optional;
    };
}

redef enum Notice::Type +={
    DNS::Exfiltration    
};

event connection_established(c: connection)
    {    
    local rec: Foo::Info = [$dns_query = c$dns$query];
    c$foo = rec;
    if(|c$dns$query| > 52)
        NOTICE([$note = DNS::Exfiltration, $msg=fmt("Long Domain. Possible DNS exfiltration/tunnel by %s. Offending domain name:%s", c$id$resp_h, c$dns$query]);
    }

event bro_init() &priority=5
    {
    Log::create_stream(Foo::LOG, [$columns=Info, $path="foo"]);
    }

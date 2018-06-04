module Foo;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts: time        &log;
        id: conn_id     &log;
        service: string &log &optional;
        missed_bytes: count &log &default=0;
    };

    global log_foo: event(rec: Info);


    redef enum Notice::Type +={
        DNS::Exfiltration    
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {    
    if(|query| > 52)
        NOTICE([$note = DNS::Exfiltration, $msg=fmt("Long Domain. Possible DNS exfiltration/tunnel by %s. Offending domain name:%s", c$id$resp_h, c$dns$query)]);
    }


event bro_init() &priority=5
    {
    Log::create_stream(Foo::LOG, [$columns=Info, $ev = log_foo, $path="foo"]);
    }

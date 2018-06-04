module Foo;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts: time        &log;
        id: conn_id     &log;
    };

    global log_dns: event(rec: Info);
}

redef enum Notice::Type +={
    Exfiltration    
};

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {    
    if(|query| > 52)
        NOTICE([$note = Exfiltration, $msg=fmt("Long Domain. Possible DNS exfiltration/tunnel by %s. Offending domain name:%s", c$id$resp_h, c$dns$query)]);
    }


event bro_init() &priority=5
    {
    Log::create_stream(Foo::LOG, [$columns=Info, $ev = log_dns, $path="foo"]);
    }

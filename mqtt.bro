
module MQTT;
export {
    redef enum Log::ID += { LOG };
    redef enum Notice::Type +={ Mqtt::Subscribe };
    type Info: record {
        ts: time        &log;
        id: conn_id     &log;
        msg_type: string &log;
        msg_len: count  &log;
        topic: string &log;
    };
}

event new_connection(c: connection){
    get_info(c); 
}

function get_info(c: connection){
    #8 is subscribe request
    if(c?$msg_type == 8 ){
TICE([$note = Mqtt::Subscribe, $msg=fmt("%s attempts to subscribe to all topics.", c$id$orig_h)]);

    }
}


event bro_init() &priority=5
    {
    Log::create_stream(Foo::LOG, [$columns=Info, $path="MQTT"]);
    }                                                        }

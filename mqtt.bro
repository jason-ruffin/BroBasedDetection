
module MQTT;
export {
    redef enum Log::ID += { LOG };
    redef enum Notice::Type +={ Mqtt:Subscribe };
    type Info: record {
        ts: time        &log;
        id: conn_id     &log;
        msg_type: string &log;
        msg_len: count  &log;
        topic: string &log;
    };
}

#event mqtt_subscribe() &priority=5{
#    local info: Info;
#    info$ts = 
#}


event bro_init() &priority=5
    {
    Log::create_stream(Foo::LOG, [$columns=Info, $path="MQTT"]);
    }                                                        }


module MQTT;
export {
    redef enum Log::ID += { LOG };
    redef enum Notice::Type +={ Mqtt::Subscribe };
    type Info: record {
        ts: time        &log;
        id: conn_id     &log;
    };
}

event packet_contents(c: connection, contents: string){
    NOTICE([$note = Mqtt::Subscribe, $msg=fmt("%s attempts to subscribe to all topics.", c$id$orig_h)]);
}

event bro_init() &priority=5
    {
    Log::create_stream(MQTT::LOG, [$columns=Info, $path="MQTT"]);
    }

module MQTT;
 export {
     redef enum Log::ID += { LOG };
     redef enum Notice::Type +={ Mqtt::Subscribe };
     type Info: record {
         ts: time        &log;
         id: conn_id     &log;
         msg_type: string &log;
         msg_len: string &log;
         topic: string  &log &optional;
         topic_len: string  &log &optional;

     };
 }


 event packet_contents(c: connection , contents: string){
    NOTICE([$note = Mqtt::Subscribe, $msg=fmt("%s attempts to subscribe to all topics.", c$id$orig_h)]);
    local info: Info;
    info$ts = c$start_time;
    info$id = c$id;
    info$msg_type = contents[:1];
    info$msg_len = contents[:3];
    if(info$msg_type == "\x82"){
        info$topic_len = contents[2:4];
        info$topic = contents[5:];
        Log::write(MQTT::LOG, info);
    }

 }

 event bro_init() &priority=5
     {
     Log::create_stream(MQTT::LOG, [$columns=Info, $path="MQTT"]);
     }

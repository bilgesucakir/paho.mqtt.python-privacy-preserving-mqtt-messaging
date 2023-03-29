import paho.mqtt.client as mqtt
import time
import random
from diffiehellman import DiffieHellman
import logging
logging.basicConfig(level=logging.DEBUG)

def connect_mqtt(id_client ) -> mqtt:
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("Connected to MQTT Broker!")
            global connack_s 
            connack_s = True
        else:
            print("Failed to connect, return code %d\n", rc)

    
    client = mqtt.Client(client_id=id_client)
    client.on_connect = on_connect
    client.connect("127.0.0.1")
    return client

def publish(client: mqtt) -> mqtt:
    def on_publish(client, obj, mid):
        print("Publish message send")
         

    client.on_publish = on_publish
    global dh2
    dh2 = DiffieHellman(group=14, key_bits=540)
    dh2_public = dh2.get_public_key()
    print("client_public  ", dh2_public )
    client.publish("AuthenticationTopic", dh2_public, qos = 2)
    return client



def subscribe(client: mqtt, id_client):
    def on_message(client, userdata, msg):
        print(f"Broker public key received `{msg.payload}` from `{msg.topic}` topic")
        global broker_public_key 
        broker_public_key = msg.payload
        global suback_s 
        suback_s = True
    client.subscribe(id_client, 2)
    client.on_message = on_message
    return client



connack_s = False
suback_s = False

 



def run():
    id_client = str(random.randint(0, 100000000))
    client = connect_mqtt(id_client)
    client.loop_start() 
    while connack_s != True:    
        time.sleep(0.1)
    if connack_s == True:
        subscribe(client, id_client)
    while suback_s != True:    
        time.sleep(0.1)
    if suback_s == True:
        publish(client)
        #pub = bytes(broker_public_key, 'utf-8')
        dh2_shared = dh2.generate_shared_key(broker_public_key)
        print("shared key   ",dh2_shared)

    logger = logging.getLogger(__name__)
    client.enable_logger(logger)
    client.loop_stop()


broker_address = "127.0.0.1"


if __name__ == '__main__':
    run()
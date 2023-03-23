import paho.mqtt.client as mqtt
import time
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import logging
logging.basicConfig(level=logging.DEBUG)


def connect_mqtt(id_client) -> mqtt:
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("Connected to MQTT Broker!")
        else:
            print("Failed to connect, return code %d\n", rc)

    
    client = mqtt.Client(client_id=id_client)
    client.on_connect = on_connect
    client.connect("127.0.0.1")
    return client

def publish(client: mqtt) -> mqtt:
    def on_publish(client, obj, mid):
        print("mid: "+str(mid))

    client.on_publish = on_publish
    return client



def subscribe(client: mqtt, id_client):
    def on_message(client, userdata, msg):
        print(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")
        print(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")

    client.subscribe(id_client, 2)
    client.on_message = on_message
    return client



'''
def DiffieHellman():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    client_private_key = parameters.generate_private_key()

    shared_key = client_private_key.exchange(server_private_key.public_key())

'''

def run():
    id_client = str(random.randint(0, 100000000))
    client = connect_mqtt(id_client)
    subscribe(client, id_client)
    logger = logging.getLogger(__name__)
    client.enable_logger(logger)
    client.loop_forever()


broker_address = "127.0.0.1"


if __name__ == '__main__':
    run()
import src.paho_folder.mqtt.client as mqtt
import time
import datetime
import random
from diffiehellman import DiffieHellman
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from os.path import exists, join

logging.basicConfig(level=logging.DEBUG)


def cert_read_fnc():
        """Burcu: START 30Mart"""
        cert_dir = "."
        CERT_FILE = "./cert_create/key.pem"
        C_F = join(cert_dir, CERT_FILE)
        private_key = "None"
        try: 
            if exists(C_F):
                with open(CERT_FILE, "rb") as key_file:
                    private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password= None,
                ) 
                
            if (private_key != "None"):
                public_key = private_key.public_key()
                private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
                )
                private_pem.splitlines()[0]
                
                #print("X509 Private key of Client: ", private_pem )
                public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                public_pem.splitlines()[0]

                with open("./cert_create/certificate.pem", "rb") as key_file:
                    x509 = load_pem_x509_certificate(
                        key_file.read()  
                    )
                    public_key2 = x509.public_key()
                    pem2 = public_key2.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    pem2.splitlines()[0]

                    #print("X509 Public key of Client", pem2)
                    
                    x509_pem = x509.public_bytes(encoding=serialization.Encoding.PEM)
                    print("X509 Certificate of Client", x509_pem)
            else: 
               print("Client cannot read the cerficate")

        except:
            print("Client cannot read the cerficate")  
        


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
    dh2 = DiffieHellman(group=14, key_bits=256) #bilgesu: key size increased to 2048
    dh2_public = dh2.get_public_key()
    print("client_public  ", dh2_public )
    client.publish("AuthenticationTopic", dh2_public, qos = 2)
    return client



def subscribe(client: mqtt, id_client):
    def on_message(client, userdata, msg):
        print(f"Broker public key received `{msg.payload}` from `{msg.topic}` topic")
        pub_key = msg.payload
        global broker_public_key 
        broker_public_key = pub_key[2:]
        print("Broker public key received", broker_public_key)
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
    cert_read_fnc()
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

    inp = ""
    while inp != "y":
        inp = input("do you want to disconnect? y/n")
        if inp == "y":
            client.disconnect()

    client.loop_stop()


broker_address = "127.0.0.1"


if __name__ == '__main__':
    run()
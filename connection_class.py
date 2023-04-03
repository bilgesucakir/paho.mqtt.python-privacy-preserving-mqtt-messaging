import src.paho_folder.mqtt.client as mqtt
import time
import datetime
import random
from diffiehellman import DiffieHellman
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from os.path import exists, join
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class MyMQTTClass(mqtt.Client):

    def __init__(self):
        self.client_x509_private_key = "None"
        self.client_x509_public_key = "None"
        self.client_x509 = "None"
        self.key_establishment_state = 1 
        self.client_diffiehellman = "None"
        self.client_dh_public_key = "None"
        self.broker_dh_public_key = "None"
        self.shared_key = "None"
        self.broker_x509 = "None"
        self.id_client = "None"
        self.disconnect_flag = False
        self.verified = False


    def cert_read_fnc(self):
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
                    
                    print("X509 Public key of Client", pem2)

                    x509_pem = x509.public_bytes(encoding=serialization.Encoding.PEM)
                    #print("X509 Certificate of Client", x509_pem)
                    self.client_x509 = x509
                    self.client_x509_private_key = private_key
                    self.client_x509_public_key = public_key
                    logger.debug("hey")
            else: 
               print("Client cannot read the cerficate")

        except:
            print("Client cannot read the cerficate")  
        
    
    def connect_mqtt(self, id_client) -> mqtt:
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                print("Connected to MQTT Broker!")
                self.key_establishment_state = 2
            else:
                 print("Failed to connect, return code %d\n", rc)


        client = mqtt.Client(client_id=id_client)
        client.on_connect = on_connect
        client.connect("127.0.0.1")
        return client

    def publish1(self, client: mqtt) -> mqtt:
        def on_publish(client, obj, mid):
            print("Publish message send")
            self.key_establishment_state = 7
         

        client.on_publish = on_publish
        dh = DiffieHellman(group=14, key_bits=2048) #bilgesu: key size increased to 2048
        dh_public = dh.get_public_key()
        self.client_diffiehellman = dh
        self.client_dh_public_key = dh_public
        print("Client Diffie Hellman Public Key:  ", dh_public )
        try:
            client_ID_byte = bytes(self.id_client, 'UTF-8')
            message = self.client_dh_public_key + b'::::' + client_ID_byte
            print("MESSAGE: " , message)
            signature = self.client_x509_private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                    ),
                hashes.SHA256()
                )
        except Exception as e3:
               print("XXXXXXXXXXXXERROR %r ", e3.args)

        client_x509_pem = self.client_x509.public_bytes(encoding=serialization.Encoding.PEM)
        data_to_sent = client_x509_pem + b'::::' + dh_public + b'::::' + signature
        print("CLIENT SIGNATURE: ", signature)
        client.publish("AuthenticationTopic", data_to_sent, qos = 2)
        self.key_establishment_state = 6
        return client



    def subscribe1(self, client: mqtt, id_client):
        def on_message(client, userdata, msg):
            if (self.key_establishment_state == 3):    
                print(f"ALL DATA `{msg.payload}` from `{msg.topic}` topic")
                data = msg.payload
                data_len = data[0:2]
                actual_data = data[2:]
                index1 = actual_data.index(b'::::')
                broker_x509_pem = actual_data[0:index1]
                pub_and_sign = actual_data[index1:]
                pub_and_sign = pub_and_sign[4:]
                index2 = pub_and_sign.index(b'::::')
                broker_dh_public_key = pub_and_sign[0:index2]
                broker_rsa_sign = pub_and_sign[index2 + 4 :]
                print("BROKER X509 CERTIFICATE: ",broker_x509_pem)
                print("BROKER DIFFIE HELLMAN PUBLIC KEY:", broker_dh_public_key)
                print("BROKER RSA SIGN: ", broker_rsa_sign)
                self.broker_dh_public_key = broker_dh_public_key
            
        
                self.key_establishment_state = 5
                broker_x509_bytes = bytes(broker_x509_pem)
                broker_x509 = load_pem_x509_certificate(broker_x509_bytes )
                self.broker_x509 = broker_x509
                broker_x509_public_key = broker_x509.public_key()
                broker_x509_public_key_pem = broker_x509_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                print("####### BROKER X509 PUBLIC KEY %s", broker_x509_public_key_pem)
                client_ID_byte = bytes(self.id_client, 'UTF-8')
                message = broker_dh_public_key + b'::::' + client_ID_byte
                message_bytes = bytes(message)
                broker_rsa_sign_bytes = bytes(broker_rsa_sign)
                print("#######MESSAGE IN BROKER RSA SIGN: %s", message_bytes)
                try:
                    broker_x509_public_key.verify(
                        broker_rsa_sign_bytes,
                        message_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )  
                    print("#####VERIFIED")
                    self.verified = True
                 
                except:
                    print("NOT VERIFIED")
                    self.disconnect_flag = True
            elif (self.key_establishment_state == 7):
                print(f"ALL DATA `{msg.payload}` from `{msg.topic}` topic")

        
        if (self.key_establishment_state == 2):      
            client.subscribe(id_client, 2)
            self.key_establishment_state = 3
        client.on_message = on_message
        return client
    

    
    def run(self):
        id_client = str(random.randint(0, 100000000))
        self.id_client = id_client
        client = self.connect_mqtt(id_client)
        client.loop_start() 
        self.cert_read_fnc()
        while self.key_establishment_state != 2:    
            time.sleep(0.1)
        if self.key_establishment_state == 2:
            self.subscribe1(client, id_client)
        print("211", self.key_establishment_state)
        while self.key_establishment_state != 5:    
            time.sleep(0.1)
        while self.verified != True:
            time.sleep(0.1)
        print("215", self.key_establishment_state)
        if self.key_establishment_state == 5:
            self.publish1(client)
            dh_shared = self.client_diffiehellman.generate_shared_key(self.broker_dh_public_key)
            print("SHARED KEY:   ",dh_shared)
            self.shared_key = dh_shared
        print("221", self.key_establishment_state)
        while self.key_establishment_state != 7:    
            time.sleep(0.1)
        if self.key_establishment_state == 7:
            self.subscribe1(client, id_client)
        while self.disconnect_flag != True:
            inp = input("do you want to disconnect? y/n")
            if inp == "y":
                self.disconnect_flag = True
              
        if (self.disconnect_flag == True):
            client.disconnect()

        #client.loop_stop()



mqttc = MyMQTTClass()
rc = mqttc.run()


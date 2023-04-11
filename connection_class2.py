import src.paho_folder.mqtt.client as mqtt
import time
import datetime
import random
from diffiehellman import DiffieHellman
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from os.path import exists, join
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.backends import default_backend
from django.utils.encoding import force_bytes, force_str
import secrets
import asyncio
from src.paho_folder.mqtt.client import Client
from tkinter import* 
from tkinter import  messagebox 
from binascii import unhexlify



logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

MQTT_ERR_NO_CONN = 4




class MyMQTTClass(mqtt.Client):

    def on_publish(self, mqttc, obj, mid):
            print("Publish message send, mid:",str(mid))

    def on_subscribe(self, mqttc, obj, mid, granted_qos):
        print("Subscribed: "+str(mid)+" "+str(granted_qos))

    def __init__(self):
        
        self.client_x509_private_key = None
        self.client_x509_public_key = None
        self.client_x509 = None
        self.key_establishment_state = 1
        self.client_diffiehellman = None
        self.client_dh_public_key = None
        self.broker_dh_public_key = None
        self.dh_shared_key = None
        self.broker_x509 = None
        self.id_client = None
        self.disconnect_flag = False
        self.verified = False
        self.session_key = None
        self.nonce1 = None
        self.nonce2 = None
        self.comming_client_id = None
        self.nonce3 = None
        self.authenticated = False
        self.choiceTokenDictionary = {}
        self.choice_token_state = 0
        self.choice_state_dict = {}

        #fix for now, will be checked later
        self._sock = None
        self._sockpairR = None
        self._sockpairW = None

        self._dontreconnect = False
        #fix for now, will be checkec later

        



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

                print("X509 Private key of Client: ", private_pem )
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
                data = "Connected to MQTT Broker!"
                print("Connected to MQTT Broker!")
                self.key_establishment_state = 2
                #var1.set(data)
            else:
                 print("Failed to connect, return code %d\n", rc)


        client = mqtt.Client(client_id=id_client)
        client.on_connect = on_connect
        client.connect("127.0.0.1")
        return client

    def publish1(self, client: mqtt) -> mqtt:
        def on_publish(client, obj, mid):
            print("Publish1 message send, mid=",str(mid))
            self.key_establishment_state = 7


        client.on_publish = on_publish
        dh = DiffieHellman(group=14, key_bits=256) #bilgesu: key size increased to 2048
        dh_public = dh.get_public_key()
        self.client_diffiehellman = dh
        self.client_dh_public_key = dh_public
        print("Client Diffie Hellman Public Key:  ", dh_public )
        try:
            client_ID_byte = bytes(self.id_client, 'UTF-8')
            message = self.client_dh_public_key  + b'::::'+ self.nonce1 + b'::::' + client_ID_byte #nonce added

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
               print("Exception: %r ", e3.args)

        client_x509_pem = self.client_x509.public_bytes(encoding=serialization.Encoding.PEM)
        data_to_sent = client_x509_pem + b'::::' + dh_public + b'::::' + self.nonce1 + b'::::' + signature #nonce added

        print("CLIENT SIGNATURE: ", signature)

        client.publish("AuthenticationTopic", data_to_sent, qos = 2)

        self.key_establishment_state = 6

        return client

    def publish2(self, client: mqtt) -> mqtt:
        def on_publish(client, obj, mid):
            print("Publish2 message send, mid=",str(mid))
            self.key_establishment_state = 10

        client.on_publish = on_publish

        backend = default_backend()
        nonce3 = secrets.token_urlsafe()

        self.nonce3 = bytes(nonce3, 'utf-8') #nonce3 setted for later
        value_str = force_str(self.nonce2) + "::::" + nonce3 + "::::" + self.id_client
        value = force_bytes(value_str)

        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(value) + padder.finalize()
        encrypted_text = encryptor.update(padded_data) + encryptor.finalize()

        client.publish("AuthenticationTopic", encrypted_text , qos = 2)

        self.key_establishment_state = 9
        return client

    def publish3(self, client: mqtt, topicName, message) -> mqtt:
        def on_publish(client, obj, mid):
            print("Publish3 message send, mid=",str(mid))
            

        client.on_publish = on_publish

        topicName_byte = force_bytes(topicName)
        choiceTokenhex = self.choiceTokenDictionary[topicName]
        choiceToken = unhexlify(choiceTokenhex)
        print("224 Choice token from dictionary:",self.choiceTokenDictionary[topicName])
        print("225 Topic name from dictionary:",topicName)

        
     
        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(topicName_byte)
        signature = h.finalize()

        topic_publish = topicName_byte + b'::::' + signature

        backend = default_backend()
        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(topic_publish) + padder.finalize()
        encrypted_topic = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_topic_hex = encrypted_topic.hex()

        message_byte = force_bytes(message)

        choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
        print("245 choiceTokenKEY: ", choicetoken_key)



        encryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).padder()
        padded_data = padder.update(message_byte) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_message_byte = force_bytes(encrypted_message)


        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(encrypted_message_byte)
        signature2 = h.finalize()

        message_publish = encrypted_message_byte + b'::::' + signature2


        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(message_publish) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

        client.publish(encrypted_topic_hex, encrypted_message , qos = 2)

       
        return client

 
    #Start: 4 Nisan
    def publishForChoiceToken(self, client: mqtt,topicname1x) -> mqtt:

        def on_publish(client, obj, mid):
            print("Publish publishForChoiceToken message send, mid=",str(mid))

        client.on_publish = on_publish

        try:
            #print(type(self.client_x509_private_key))
            #print(type(self.session_key))
            message = b'choiceToken'

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()
            print("signature in publishForChoiceToken:", signature)

            topicName = message + b'::::' + signature
            print("topicName in publishForChoiceToken:", topicName)

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(topicName) + padder.finalize()
            topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
            print("len of encrypted topicName byte: ",len(topicNameEncryptedByte))
            #print(topicNameEncryptedByte)

            topicNameEncryptedHex = topicNameEncryptedByte.hex()
            print("len of hex of topic name byte: ",len(topicNameEncryptedHex))
            #topicNameEncryptedHex = topicNameEncryptedHex[1:]
            print("topicNameEncryptedByte: ", topicNameEncryptedByte)
            print("topicNameEncryptedHex: ", topicNameEncryptedHex)


            #topicWanted = b'light'
            topicWanted = force_bytes(topicname1x)
            print("topicWanted : ",topicWanted)
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(topicWanted)
            signature = h.finalize()
            payload = topicWanted + b'::::' + signature
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(payload) + padder.finalize()
            payloadByte = encryptor.update(padded_data) + encryptor.finalize()


            client.publish(topicNameEncryptedHex, payloadByte , qos = 2)
            self.choice_state_dict[topicname1x] = 1

        except Exception as e3:
               print("Exception: %r ", e3.args)



    def subscribe2(self, client: mqtt, id_client):
        def on_message(client, userdata, msg):
            print(f"ALL DATA `{msg.payload}` from `{msg.topic}` topic")
            data = msg.payload
            data_len = data[0:2]
            actual_data = data[2:]
            #print(data_len)
            print("actual data:", actual_data)
            
            backend = default_backend()
            decryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).decryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).unpadder()
            decrypted_data = decryptor.update(actual_data) 
            unpadded = padder.update(decrypted_data) + padder.finalize()

            indexMAC = unpadded.rfind(b'::::')
            topic_and_choiceTokens = unpadded[0:indexMAC]
            mac_of_choice_token = unpadded[indexMAC+4:]
            print("mac_of_choice_token", mac_of_choice_token)
            print("topic_and_choiceTokens", topic_and_choiceTokens)


            
            index1 = topic_and_choiceTokens.index(b'::::')
            topicName = topic_and_choiceTokens[0:index1]
            choiceToken = topic_and_choiceTokens[index1+4:]
            
            print("choiceToken: ", choiceToken)

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(topic_and_choiceTokens)
            signature = h.finalize()

            if(mac_of_choice_token == signature):
                print("The content of the message has not been changed ")
                topicName_str = bytes.decode(topicName)

                print("choicetoken 367: ", choiceToken)

                choiceTokenHex = choiceToken.hex()

                print("choicetokenhex  371:", choiceTokenHex)


                self.choiceTokenDictionary[topicName_str] = choiceTokenHex
                print("dictionary of given topicName:", self.choiceTokenDictionary)
                self.choice_state_dict[topicName_str] = 2
            else:
                print("The content of the message has been changed.")

        client.on_message = on_message

        if (self.choice_token_state == 0):

            message_str = self.id_client
            message = bytes(message_str, 'utf-8')

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()

            topicName = message + b'::::' + signature

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(topicName) + padder.finalize()
            topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
            topicNameEncryptedHex = topicNameEncryptedByte.hex()

            client.subscribe(topicNameEncryptedHex, 2)
            self.choice_token_state = 1

        return client
    


    def subscribe3(self, client: mqtt, topicname):
        def on_message(client, userdata, msg):
            print(f"ALL DATA `{msg.payload}` from `{msg.topic}` topic")

            topic_hex = msg.topic
            topic_byte = unhexlify(topic_hex)
            backend = default_backend()
            decryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).decryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).unpadder()
            decrypted_data = decryptor.update(topic_byte)
            unpadded = padder.update(decrypted_data) + padder.finalize()

            index1 = unpadded.index(b'::::')
            topic_name = unpadded[0:index1]
            mac_of_topic_name = unpadded[index1+4:]

            topic_name_str = bytes.decode(topic_name)
            choiceTokenhex = self.choiceTokenDictionary[topic_name_str]
            choiceToken = unhexlify(choiceTokenhex)
            print("Choice token from dictionary:",self.choiceTokenDictionary[topic_name_str])
            print("Topic name from dictionary:",topic_name_str)



            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(topic_name)
            signature = h.finalize()

            if(signature == mac_of_topic_name):
                print("The content of the topic name is not changed")

                data = msg.payload
                data_len = data[0:2]
                actual_data = data[2:]

                decryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).decryptor()
                padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).unpadder()
                decrypted_data = decryptor.update(actual_data)
                unpadded = padder.update(decrypted_data) + padder.finalize()
                index1 = unpadded.index(b'::::')

                message_encrypted_with_ct = unpadded[0:index1]
                mac_of_payload = unpadded[index1+4:]    #change mac of payload after update

                choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
                print("choicetoken_key ", choicetoken_key)

                decryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).decryptor()
                padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).unpadder()
                decrypted_data2 = decryptor.update(message_encrypted_with_ct)
                unpadded_message = padder.update(decrypted_data2) + padder.finalize()

                h = hmac.HMAC(self.session_key, hashes.SHA256())
                h.update(message_encrypted_with_ct)
                signature = h.finalize()

                if(signature == mac_of_payload):
                    print("The content of the payload is not changed")
                    print("MESSAGE: " ,unpadded_message, "FROM ", topic_name )

                else:
                    print("The content of the payload is changed")




            else:
                print("The content of the topic name is changed")


            
        if(self.choice_state_dict[topicname] == 2):

            client.on_message = on_message
            topicName_byte = force_bytes(topicname)   
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(topicName_byte)
            signature = h.finalize()
             

            topicName_subscribe = topicName_byte + b'::::' + signature

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(topicName_subscribe) + padder.finalize()
            topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
            topicNameEncryptedHex = topicNameEncryptedByte.hex()

            client.subscribe(topicNameEncryptedHex, 2)
            self.choice_state_dict[topicname] = 3
        

        return client












    async def subscribe1(self, client: mqtt, id_client):
        def on_message(client, userdata, msg):
            if (self.key_establishment_state == 3):
                print(f"ALL DATA `{msg.payload}` from `{msg.topic}` topic")
                data = msg.payload

                data_len = data[0:2]
                actual_data = data[2:]
                index1 = actual_data.index(b'::::')

                broker_x509_pem = actual_data[0:index1]
                nonce_pub_and_sign = actual_data[index1+4:]


                index2 = nonce_pub_and_sign.index(b'::::')
                broker_dh_public_key = nonce_pub_and_sign[0:index2]

                nonce_rsa_sign = nonce_pub_and_sign[index2 + 4 :]

                index3 = nonce_rsa_sign.index(b'::::')
                nonce_1 = nonce_rsa_sign[0:index3]
                self.nonce1 = nonce_1

                broker_rsa_sign = nonce_rsa_sign[index3+4:]

                print("BROKER X509 CERTIFICATE: ",broker_x509_pem)
                print("BROKER DIFFIE HELLMAN PUBLIC KEY:", broker_dh_public_key)
                print("NONCE_1: ", nonce_1)
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
                message = broker_dh_public_key + b'::::' + self.nonce1 + b'::::' + client_ID_byte
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

                    self.disconnect()


            elif (self.key_establishment_state == 7):

                print(f"ALL DATA `{msg.payload}` from `{msg.topic}` topic")

                data = msg.payload

                data_len = data[0:2]
                actual_data = data[2:]
                backend = default_backend()

                sessionkey = force_bytes(base64.urlsafe_b64encode(force_bytes(self.dh_shared_key))[:32])

                self.session_key = sessionkey

                decryptor = Cipher(algorithms.AES(sessionkey), modes.ECB(), backend).decryptor()
                padder = padding2.PKCS7(algorithms.AES(sessionkey).block_size).unpadder()

                decrypted_data = decryptor.update(actual_data)

                unpadded = padder.update(decrypted_data) + padder.finalize()

                print("unpadded", unpadded)

                index1 = unpadded.index(b'::::')
                comming_nonce2_or_clientId = unpadded[0:index1]
                comming_client_id_orNotAuth = unpadded[index1+4:]
                print(type(comming_client_id_orNotAuth), "set incoming id")
                print("332")
                if(bytes.decode(comming_nonce2_or_clientId,"utf-8") == self.id_client and comming_client_id_orNotAuth == b'notAuthenticated'):
                    print("334")
                    #not auth received from broker

                    self._dontreconnect = True
                    self.disconnect_flag = True

                    self.disconnect()


                else:
                    self.nonce2 = comming_nonce2_or_clientId #set nonce2
                    self.comming_client_id = comming_client_id_orNotAuth

                    print("comming_nonce2", comming_nonce2_or_clientId)
                    print("comming_client_id", comming_client_id_orNotAuth)
                    print(self.id_client)



            elif (self.key_establishment_state == 10):
                print("inside function")
                print(f"ALL DATA `{msg.payload}` from `{msg.topic}` topic")

                data = msg.payload

                data_len = data[0:2]
                actual_data = data[2:]

                print(actual_data, "**************actual data")

                backend = default_backend()
                decryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).decryptor()
                padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).unpadder()


                decrypted_data = decryptor.update(actual_data)
                unpadded = padder.update(decrypted_data) + padder.finalize()

                print("unpadded message 10", unpadded)

                index1 = unpadded.index(b'::::')
                comming_nonce3 = unpadded[0:index1]
                comming_client_id = unpadded[index1+4:]
                #print("377")
                if(bytes.decode(comming_nonce3,"utf-8") == self.id_client and comming_client_id == b'notAuthenticated'):
                    #not auth received from broker
                    #print("380")

                    self._dontreconnect = True
                    self.disconnect()
                    self.disconnect_flag = True



                else:
                    if comming_nonce3 == force_bytes(self.nonce3) and comming_client_id == force_bytes(self.id_client):
                        print("BROKER IS AUTHENTICATED")
                        self.authenticated = True
                    else:
                        print("BROKER CANNOT BE AUTHENTICATED")
                        self.disconnect_flag = True

                        self.disconnect()


            else:

                message = msg.payload
                if message == self.id_client:
                    print("Key establishment failed. Disconnect, do not reconnect untill establishing a new connection with a new key establishment state.")
                    Client._dontreconnect = True #variable set to true to prevent reconnect in this session.


                print("inside function")
                print(f"ALL DATA `{msg.payload}` from `{msg.topic}` topic")
                print("something went wrong")


        client.on_message = on_message

        if (self.key_establishment_state == 2):

            client.subscribe(id_client, 2)
            self.key_establishment_state = 3


        return client




    async def run1(self):

        id_client = str(random.randint(0, 100000000))
        self.id_client = id_client
        client = self.connect_mqtt(id_client)

        client.loop_start()
        self.cert_read_fnc()
        while self.key_establishment_state != 2:
            time.sleep(0.1)
        if self.key_establishment_state == 2:
            await self.subscribe1(client, id_client)
        print("current key establishment state after subs1 call:", self.key_establishment_state)
        while self.key_establishment_state != 5:
            time.sleep(0.1)

        print("current key establishment state (should be 5)", self.key_establishment_state)
        if self.key_establishment_state == 5:
            self.publish1(client)
            dh_shared = self.client_diffiehellman.generate_shared_key(self.broker_dh_public_key)
            print("SHARED KEY:   ",dh_shared)
            self.dh_shared_key = dh_shared
        print("current key establishment state (after publish1)", self.key_establishment_state)
        while self.key_establishment_state != 7:
            time.sleep(0.1)
        if self.key_establishment_state == 7:
            await self.subscribe1(client, id_client)
        #print("hey1")

        while self.comming_client_id == None:
            time.sleep(0.1)
        if self.comming_client_id != None:
            incomingClientIdByte = self.comming_client_id


            #print(type(incomingClientIdByte))
            #print(type(self.id_client))
            if (bytes.decode(incomingClientIdByte, 'utf-8') == self.id_client ):
                self.key_establishment_state = 8
                print("Comming client id matches with this client's id")
                print("Message encrypted with ") #is it needed
                print(self.key_establishment_state)
            else:
                self.disconnect_flag = True
                self.disconnect()

        while self.key_establishment_state != 8:
            time.sleep(0.1)

        if self.key_establishment_state == 8:
            print("Current key establishment state is 8.")
            self.publish2(client)

        stopWhile = False #bilgesu modification

        while self.key_establishment_state != 10:
            time.sleep(0.1)
        if self.key_establishment_state == 10:
            print("Current key establishment state is 10.")
            await self.subscribe1(client, id_client)

            while (self.authenticated == False and stopWhile == False): #bilgesu modification
                time.sleep(0.1)

                if(self._dontreconnect == True): #bilgesu modification
                    self.disconnect_flag = True
                    stopWhile = True

            if (self.authenticated == True):
                print("Authenticated true")
                self.subscribe2(client, id_client)
                self.choice_token_state = 1


            if (self.authenticated == True):
                print("Authenticated. Key establishment finished.")
                #self.publishForChoiceToken(client)  #error in the function
                return client
            else:
                return -1


        #client.loop_stop()

    async def run2(self,client,topicname1):
            print("run2 function call, topicname: ",topicname1)
            

            if (self.disconnect_flag == False):
                self.choice_state_dict[topicname1] = 0
                self.publishForChoiceToken(client,topicname1)

            while (self.choice_state_dict[topicname1] != 1 and self.disconnect_flag == False):
                    time.sleep(0.1)
            if (self.choice_state_dict[topicname1] == 1 and self.disconnect_flag == False):
                self.subscribe2(client, self.id_client)

            while (self.choice_state_dict[topicname1] != 2 and self.disconnect_flag == False):
                    time.sleep(0.1)
            if (self.choice_state_dict[topicname1] == 2 and self.disconnect_flag == False):
                self.subscribe3(client, topicname1)

            return client
    
    async def run3(self,client,topicname1, message):
            print("run3 function call, topicname: ",topicname1)
                       
            if (self.disconnect_flag == False):
                self.choice_state_dict[topicname1] = 0
                self.publishForChoiceToken(client,topicname1)

            while (self.choice_state_dict[topicname1] != 1 and self.disconnect_flag == False):
                    time.sleep(0.1)
            if (self.choice_state_dict[topicname1] == 1 and self.disconnect_flag == False):
                self.subscribe2(client, self.id_client)

            while (self.choice_state_dict[topicname1] != 2 and self.disconnect_flag == False):
                    time.sleep(0.1)

            if (self.choice_state_dict[topicname1] == 2 and self.disconnect_flag == False):
                self.publish3(client, topicname1, message)






            return client
        #client.loop_stop()
"""
mqttc = MyMQTTClass()
client = asyncio.run(mqttc.run1())
print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
topicname1="test1111"
rc = asyncio.run(mqttc.run2(client,topicname1))
print(" rc = asyncio.run(mqttc.run2(mqttc,topicname)) , rc :",rc)


while mqttc.disconnect_flag != True:
        inp = input("do you want to disconnect? y/n")
        if inp == "y":
                mqttc.disconnect_flag = True

        if (mqttc.disconnect_flag == True):

            if(mqttc._dontreconnect == True): #bilgesu modification
                print("Disconnecting from broker since client is not authenticated and key establishment has stopped.")
            else:
                print("Disconnecting from broker")
            returned = mqttc.disconnect()
"""
"""
window= Tk()
mywin=MyWindow(window)
window.geometry('600x600')
window.title("MQTT CLIENT")
window.mainloop()
"""

#mqttc.loop_stop()


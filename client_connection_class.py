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

    def __init__(self):
        super().__init__()   # önce super init fonksiyonunu çağırmak gerekir
        #self.disconnect_flag = False
        self.connected_flag =False
        self._client_id = b''
        self.msg = None
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

        self.fail_to_verify_mac = False

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

   

    def on_connect_fail(self, mqttc, obj):
        print("###140 on_connect_fail)----Connect failed")

    def on_message(self, mqttc, obj, msg):
        print("###143 on_message()----PUBLISH message received, topic: " + msg.topic+" "+str(msg.qos)+" "+str(msg.payload))
        print(f" ###143 ALL DATA `{msg.payload}` from `{msg.topic}` topic")

    def on_publish(self, mqttc, obj, mid):
        print("###147 on_publish()----PUBLISH message sent, message id: " + str(mid))

    def on_subscribe(self, mqttc, obj, mid, granted_qos):
        print("###150 on_subscribe()----" + "Subscribed: "+str(mid)+" "+str(granted_qos))

    def on_log(self, mqttc, obj, level, string):
        print("-------153 def on_log()----"+ string)



    def on_connect(self, mqttc, obj, flags, rc):
        print("###135 on_connect()----connect successful rc: "+str(rc))
        self.connected_flag = True
        self.key_establishment_state = 2
        self.msg = "connected"
        print("YAZ ARTIK:",self.msg)

    def connect_mqtt(self, id_client) -> mqtt:
        self._client_id = id_client
        self.connect("127.0.0.1", 1883, 600)
        return self

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
               print("XXXXXXXXXXXXERROR %r ", e3.args)

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
            print(type(self.client_x509_private_key))
            print(type(self.session_key))
            message = b'choiceToken'

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()
            print(signature)

            #bilgesu modificaiton distoring signature on purpose to see the fail case
            #signature = b'distortedSignature'
            #this line will be removed
            #print("DISTORTED SIGNATURE: ", signature)


            topicName = message + b'::::' + signature
            print(topicName)

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(topicName) + padder.finalize()
            topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
            print("len: ",len(topicNameEncryptedByte))
            #print(topicNameEncryptedByte)

            topicNameEncryptedHex = topicNameEncryptedByte.hex()
            print(" len of hex: ",len(topicNameEncryptedHex))
            #topicNameEncryptedHex = topicNameEncryptedHex[1:]
            print("topicNameEncryptedByte: ", topicNameEncryptedByte)
            print("topicNameEncryptedHex: ", topicNameEncryptedHex)


            #topicWanted = b'light'
            topicWanted = force_bytes(topicname1x)
            print("topicWanted : ",topicWanted)
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(topicWanted)
            signature = h.finalize()


            #bilgesu modificaiton distoring signature on purpose to see the fail case
            #signature = "distortedSignature"
            #this line will be removed


            payload = topicWanted + b'::::' + signature
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(payload) + padder.finalize()
            payloadByte = encryptor.update(padded_data) + encryptor.finalize()


            client.publish(topicNameEncryptedHex, payloadByte , qos = 2)
            self.choice_state_dict[topicname1x] = 1

        except Exception as e3:
               print("ERROR %r ", e3.args)



    def subscribe2(self, client: mqtt, id_client):
        def on_message(client, userdata, msg):
            print(f"ALL DATA `{msg.payload}` from `{msg.topic}` topic")
            data = msg.payload
            data_len = data[0:2]
            actual_data = data[2:]
            print(data_len)
            print(actual_data)

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

            #bilgesu: modification
            if topicName == self.id_client and choiceToken == "signVerifyFailed":
                print("Received signVerifyFailed, wont get choicetoken. Following should be empty:", self.choiceTokenDictionary[topicName_str])


            else:
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
                    print(self.choiceTokenDictionary)
                    self.choice_state_dict[topicName_str] = 2
                else:
                    print("The content of the message has been changed")

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









    def subscribe4(self, client: mqtt):
        def on_message(client, userdata, msg):
            print(f"----subscribe4 on_message---ALL DATA `{msg.payload}` from `{msg.topic}` topic")

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
                    print("HATA: The content of the payload is changed")
            else:
                print("HATA: The content of the topic name is changed")


        client.on_message = on_message



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
                print("377")
                if(bytes.decode(comming_nonce3,"utf-8") == self.id_client and comming_client_id == b'notAuthenticated'):
                    #not auth received from broker
                    print("380")

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
                    self._dontreconnect = True #variable set to true to prevent reconnect in this session.


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
        print("211", self.key_establishment_state)
        while self.key_establishment_state != 5:
            time.sleep(0.1)

        print("215", self.key_establishment_state)
        if self.key_establishment_state == 5:
            self.publish1(client)
            dh_shared = self.client_diffiehellman.generate_shared_key(self.broker_dh_public_key)
            print("SHARED KEY:   ",dh_shared)
            self.dh_shared_key = dh_shared
        print("221", self.key_establishment_state)
        while self.key_establishment_state != 7:
            time.sleep(0.1)
        if self.key_establishment_state == 7:
            await self.subscribe1(client, id_client)
        print("hey1")

        while self.comming_client_id == None:
            time.sleep(0.1)
        if self.comming_client_id != None:
            incomingClientIdByte = self.comming_client_id


            print(type(incomingClientIdByte))
            print(type(self.id_client))
            if (bytes.decode(incomingClientIdByte, 'utf-8') == self.id_client ):
                self.key_establishment_state = 8
                print("same id")
                print("Message encrypted with ")
                print(self.key_establishment_state)
            else:
                self.disconnect_flag = True
                self.disconnect()

        while self.key_establishment_state != 8:
            time.sleep(0.1)

        if self.key_establishment_state == 8:
            print("state 8")
            self.publish2(client)

        stopWhile = False #bilgesu modification

        while self.key_establishment_state != 10:
            time.sleep(0.1)
        if self.key_establishment_state == 10:
            print("STATE 10")
            await self.subscribe1(client, id_client)

            while (self.authenticated == False and stopWhile == False): #bilgesu modification
                time.sleep(0.1)

                if(self._dontreconnect == True): #bilgesu modification
                    self.disconnect_flag = True
                    stopWhile = True

            if (self.authenticated == True):
                print("authenticated true")
                self.subscribe2(client, id_client)
                self.choice_token_state = 1


            if (self.authenticated == True):
                print("Authenticated. Key establishment finished.")
                #self.publishForChoiceToken(client)  #error in the function
                return client
            else:
                self.disconnect_flag = True
                self.disconnect()
                return -1


        #client.loop_stop()

    async def run2(self,client,topicname_list):

        print("-------------------run2, topicname: ")

        for topicname1 in topicname_list:


            if (self.disconnect_flag == False):
                self.choice_state_dict[topicname1] = 0
                self.publishForChoiceToken(client,topicname1)

            print("---879 length of topicname1=",len(topicname1))
            print("---879 self.choice_state_dict[topicname1]=",self.choice_state_dict[topicname1])

            while (self.choice_state_dict[topicname1] != 1 and self.disconnect_flag == False):
                    time.sleep(0.1)
            if (self.choice_state_dict[topicname1] == 1 and self.disconnect_flag == False):

                #if signVErifyFailed received do not send 
                self.subscribe2(client, self.id_client)

            #burada fialed to verify maci kontrol et. True ise tekrardan subscribe olma seçeneği gelmeli. 
            while (self.choice_state_dict[topicname1] != 2 and self.disconnect_flag == False):
                    time.sleep(0.1)
            if (self.choice_state_dict[topicname1] == 2 and self.disconnect_flag == False):
                self.subscribe3(client, topicname1)

            if (self.disconnect_flag == False) :
                self.subscribe4(client)

        return client

    async def run3(self,client,topicname1, message):
            print("-------------------run3, topicname: ",topicname1)

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

            if (self.disconnect_flag == False) :
                self.subscribe4(client)

            return client
        #client.loop_stop()


#mqttc.loop_stop()

xwindow=Tk()
var2=StringVar()
xMqttc1 = MyMQTTClass()


def deneme():
    classobj = xMqttc1
    windowobj = xwindow
    var1 = var2

    return [classobj, windowobj, var1]

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
from random import SystemRandom
from random import SystemRandom
import hashlib




logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("clientwild_logging")

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
        self.subscriber_choice_token_session = {}
        self.publisher_choice_token_session = {}

        self.fail_to_verify_mac = False

        #fix for now, will be checked later
        self._sock = None
        self._sockpairR = None
        self._sockpairW = None

        self._dontreconnect = False
        #fix for now, will be checkec later


        self.subscribe_success:list = [] 
        self.publish_success:list = [] 
       
        self.subscribe_success_topic_hash = 0
        self.publish_success_topic_hash:list = [] 


        self.unsub_success: bool = False
        self.seed_dictionary = {}                   #used by subscribers
        self.topic_hash_dictionary = {}                  #used by subscribers
        self.hash_topic_dictionary = {}                  #used by subscribers
        self.topicname_hash_dictionary = {}              #used by publishers
        self.publisher_seed_dictionary = {}        #used by publishers
        self.publisher_topic_dictionary = {}       #used by subscribers
        self.poly_list  = []                     #used by subscribers
        self.polynomials:list = []                 #used by publishers
        self.topic_subscribe_boolean = {}          #used by subscribers

       

        self.MAX_COUNT = 5
        self.count = 0
        self.count_dictionary = {}               #used by subscriber
        self.publisher_hash_session_topics = {}   #used by publisher
        self.hash_session_end = False            #used by publisher
        self.topic_hashing_clear = False         #used by subscriber



        #TEMPORARY
        self._entered_on_message = False

    def polynomial_func(self,x,a,b,c,d):
        y = a *(x*x*x) + b*(x*x) + c *(x) + d
        y = y % 9000
        y += 1000 
        print (y)
        return y


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
                #print("Private key of X509 is read from the certificate")
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

                    #print("X509 Public key of Client:", pem2)

                    x509_pem = x509.public_bytes(encoding=serialization.Encoding.PEM)

                    logger.log(logging.INFO, b'X509 Certificate of Client: \n' + x509_pem)
                    logger.log(logging.INFO, b'X509 Public key of Client: \n ' + pem2)
                    #print("X509 Certificate of Client: ", x509_pem)
                    #print("X509 Public key of Client: ", pem2)
                    self.client_x509 = x509
                    self.client_x509_private_key = private_key
                    self.client_x509_public_key = public_key

            else:
               #print("Client cannot read the cerficate")
               logger.log(logging.INFO, "Client cannot read the cerficate")

        except:
            #print("Client cannot read the cerficate")
            logger.log(logging.INFO, "Client cannot read the cerficate")





    def on_message(self, mqttc, obj, msg):
        logger.log(logging.INFO, "----Publish message was received from broker")
        logger.log(logging.INFO, b'payload: ' + msg.payload)
        logger.log(logging.INFO, 'topic: ' + msg.topic )

    def on_publish(self, mqttc, obj, mid):
        logger.log(logging.INFO, "PUBLISH message sent, message id: " + str(mid))

    def on_subscribe(self, mqttc, obj, mid, granted_qos):
        logger.log(logging.INFO, "Suback received, message id: "+ str(mid))
        if (self.authenticated == True):
            suback_packet = self.get_mac()
            index1 = suback_packet.index(b'::::')
            mac_real =  suback_packet[index1+4:]
            byte_packet_id = force_bytes(str(mid), 'utf-8')
            message = byte_packet_id + b'::::' + b'1'
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()
            if (mac_real == signature):
                logger.log(logging.INFO, "Signature of SUBACK is verified." )
            else:
                logger.log(logging.ERROR, "Signature of SUBACK is not verified." )
                self.suback_verified = False




    def on_unsubscribe(self, mqttc, obj, mid):
        packet_bytes = self.get_packet_bytes()
        logger.log(logging.INFO, "Unsuback was received, message Id: " + str(mid))

        #logger.log(logging.ERROR, "mac " + str(packet_bytes))

        index1 = packet_bytes.index(b'::::')
        mac_real =  packet_bytes[index1+4:]
        
        #logger.log(logging.ERROR, "mac " + str(mac_real))

        byte_packet_id = force_bytes(str(mid), 'utf-8')
        message = byte_packet_id 
        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(message)
        signature = h.finalize()

        #logger.log(logging.ERROR, "mac " + str(signature))

        if (mac_real == signature):
            logger.log(logging.INFO, "Signature of UNSUBACK is verified.")

        else:
            logger.log(logging.ERROR, "Signature of UNSUBACK is not verified.")

            self.unsuback_verified = False
            #need to take an action here


    def on_log(self, mqttc, obj, level, string):
        msg1 = "failed to receive on socket"
        if (string.find(msg1) != -1) :
            logger.log(logging.ERROR,"--------on_log()----"+ string)
            self.disconnect_flag = True
        else:
            logger.log(logging.INFO,"--------on_log()----"+ string)

    def on_connect_fail(self, mqttc):
        self.suppress_exceptions = True
        logger.log(logging.ERROR, "Connection failed")

    def on_connect(self, mqttc, obj, flags, rc):
        self.suppress_exceptions = True
        logger.log(logging.INFO, "Connection successful (step 2), return code: "+str(rc))
        self.connected_flag = True
        self.key_establishment_state = 2
        self.msg = "connected"

    def connect_mqtt(self, id_client) -> mqtt:
        self._client_id = id_client
        self.connect("127.0.0.1", 1883, 6000)
        logger.log(logging.INFO, "---Connection message send to broker (step 1)---")

        return self


    def publish_step6(self, client: mqtt) -> mqtt:         #diffie hellman step 6 publish

        def on_publish(client, obj, mid):
            logger.log(logging.INFO, "Publish message (step 6 of the DH Key Exchange) was send, messageID =" + str(mid))    
            self.key_establishment_state = 7
            


        client.on_publish = on_publish
        logger.log(logging.INFO, "----Function: Prepare publish message for step 6 of the DH key exchange----")

        dh = DiffieHellman(group=14, key_bits=256)
        dh_public = dh.get_public_key()
        self.client_diffiehellman = dh
        self.client_dh_public_key = dh_public
      
        try:
            client_ID_byte = bytes(self.id_client, 'UTF-8')
            message = self.client_dh_public_key  + b'::::'+ self.nonce1 + b'::::' + client_ID_byte #nonce added


            signature = self.client_x509_private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                    ),
                hashes.SHA256()
                )
        except Exception as e3:
               logger.log(logging.INFO, "ERROR %r " + e3.args)

        client_x509_pem = self.client_x509.public_bytes(encoding=serialization.Encoding.PEM)
        data_to_sent = client_x509_pem + b'::::' + dh_public + b'::::' + self.nonce1 + b'::::' + signature #nonce added
    
        logger.log(logging.INFO, "PAYLOAD TO BE SEND TO BROKER FOR STEP 6:")
        logger.log(logging.INFO, b'CLIENT X509 CERTIFICATE: ' + client_x509_pem)
        logger.log(logging.INFO, b'CLIENT DIFFIE HELLMAN PUBLIC KEY: ' + dh_public)
        logger.log(logging.INFO, b'NONCE 1: ' + self.nonce1)
        logger.log(logging.INFO, b'CLIENT RSA SIGN: ' + signature)

        #print("MESSAGE (step 6 of the DH Key Exchange): " , data_to_sent)

        client.publish("AuthenticationTopic", data_to_sent, qos = 1)

        self.key_establishment_state = 6

        return client

    def publish_step9(self, client: mqtt) -> mqtt:
        def on_publish(client, obj, mid):
            logger.log(logging.INFO, "Publish message (step 9 of the DH Key Exchange) was send, messageID =" + str(mid))
            self.key_establishment_state = 10

        client.on_publish = on_publish
        logger.log(logging.INFO, "----Function: Prepare publish message for step 9 of the DH key exchange----")

        backend = default_backend()
        nonce3 = secrets.token_urlsafe()

        self.nonce3 = bytes(nonce3, 'utf-8') #nonce3 setted for later

        logger.log(logging.INFO, "Nonce 3: " + nonce3)
        value_str = force_str(self.nonce2) + "::::" + nonce3 + "::::" + self.id_client

        value = force_bytes(value_str)

        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(value) + padder.finalize()
        encrypted_text = encryptor.update(padded_data) + encryptor.finalize()

        logger.log(logging.INFO, b'Encrypted message (step 9 of the DH Key Exchange): ' + encrypted_text)


        client.publish("AuthenticationTopic", encrypted_text , qos = 1)

        self.key_establishment_state = 9
        return client

    def publish_real_topics(self, client: mqtt, topicName, message) -> mqtt:
        def on_publish(client, obj, mid):
            logger.log(logging.INFO, "Puback was received, messageID =" + str(mid))
            puback = self.get_puback()

            #logger.log(logging.ERROR, "mac " + str(puback))

            index1 = puback.index(b'::::')
            mac_real =  puback[index1+4:]

            #logger.log(logging.ERROR, "mac " + str(mac_real))

            byte_packet_id = force_bytes(str(mid), 'utf-8')
            message = byte_packet_id 
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()

            #logger.log(logging.ERROR, "mac " + str(signature))

            if mac_real == signature:
                logger.log(logging.INFO, "Signature of PUBACK is verified.")

            else:
                logger.log(logging.ERROR, "Signature of PUBACK is not verified. You might want to make another publish.")
                #taking an action is needed or not




        client.on_publish = on_publish
        logger.log(logging.INFO, "----Function to publish to topic: " + topicName )
        logger.log(logging.INFO, "Message to be published: " + message)

        topicName_byte = force_bytes(topicName)
        choiceTokenhex = self.choiceTokenDictionary[topicName]
        choiceToken = unhexlify(choiceTokenhex)
    


        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(topicName_byte)
        signature = h.finalize()
        #signature = b'broken'

        topic_publish = topicName_byte + b'::::' + signature

        backend = default_backend()
        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(topic_publish) + padder.finalize()
        encrypted_topic = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_topic_hex = encrypted_topic.hex()
       
        logger.log(logging.INFO, "Authenticated encryption version of the topic name to be published: " + encrypted_topic_hex)

        message_byte = force_bytes(message)

        choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
        #print("245 choiceTokenKEY: ", choicetoken_key)



        encryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).padder()
        padded_data = padder.update(message_byte) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_message_byte = force_bytes(encrypted_message)
        logger.log(logging.INFO, b'Message after encryption with the choice token: '+ encrypted_message)

        qos = 1
        retainFlag = False
        msgid = self._mid_generate()
        hash_message_str = str(qos) + str(retainFlag) + str(msgid)
        #hash_message_str = str(qos) + str(retainFlag)   #for error cases
        hash_message_bytes = encrypted_message_byte + force_bytes(hash_message_str)


        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(hash_message_bytes)
        signature2 = h.finalize()

        message_publish = encrypted_message_byte + b'::::' + signature2


        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(message_publish) + padder.finalize()
        encrypted_message2 = encryptor.update(padded_data) + encryptor.finalize()
       
        logger.log(logging.INFO, b'Message after authenticated encyption with the session key: '+ encrypted_message2)

        client.publish(encrypted_topic_hex, encrypted_message2 , qos = qos, retain = retainFlag, msgid=msgid)

        self.publish_success.append(topicName)


        return client


  
    def publishForChoiceToken(self, client: mqtt,topicname1x) -> mqtt:

        def on_publish(client, obj, mid):
            logger.log(logging.INFO, "----Puback was received---- (step 3 of choice token schema) ")
            puback = self.get_puback()

            #logger.log(logging.ERROR, "mac " + str(puback))

            index1 = puback.index(b'::::')
            mac_real =  puback[index1+4:]

            #logger.log(logging.ERROR, "mac " + str(mac_real))

            byte_packet_id = force_bytes(str(mid), 'utf-8')
            message = byte_packet_id 
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()

            #logger.log(logging.ERROR, "mac " + str(signature))

            if mac_real == signature:
                logger.log(logging.INFO, "Signature of PUBACK is verified.")
            else:
                logger.log(logging.ERROR, "Signature of PUBACK is not verified.")

        client.on_publish = on_publish

        try:
            #print("----Function: Prepare publish message for step 2 of the choice token schema----")
            logger.log(logging.INFO, "----Function: Prepare publish message for step 2 of the choice token schema----")
            #print(type(self.client_x509_private_key))
            #print(type(self.session_key))
            message = b'choiceToken'

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()
            #print(signature)

            #bilgesu modificaiton distoring signature on purpose to see the fail case
            #signature = b'distortedSignature'
            #this line will be removed
            #print("DISTORTED SIGNATURE: ", signature)


            topicName = message + b'::::' + signature
            #print(topicName)

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(topicName) + padder.finalize()
            topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
            #print("len: ",len(topicNameEncryptedByte))
            #print(topicNameEncryptedByte)

            topicNameEncryptedHex = topicNameEncryptedByte.hex()
            #print(" len of hex: ",len(topicNameEncryptedHex))
            #topicNameEncryptedHex = topicNameEncryptedHex[1:]
            #print("topicNameEncryptedByte: ", topicNameEncryptedByte)
            #print("topicNameEncryptedHex: ", topicNameEncryptedHex)

            clientobj = mqtt.Client
            msgid = self._mid_generate()
            retainFlag = False
            qos = 1

            messagex = topicname1x + self.id_client + str(qos)+ str(retainFlag) + str(msgid)
            #messagex = topicname1x + self.id_client + str(qos)+ str(retainFlag)  #for error cases
            print("messagex:", messagex )
            message_byte = force_bytes(messagex)




            #topicWanted = b'light'

            #print("topicWanted : ",topicWanted)
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message_byte)
            signature = h.finalize()




            #bilgesu modificaiton distoring signature on purpose to see the fail case
            #signature = "distortedSignature"
            #this line will be removed
            topicWanted = force_bytes(topicname1x)


            payload = topicWanted + b'::::' + signature
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(payload) + padder.finalize()
            payloadByte = encryptor.update(padded_data) + encryptor.finalize()
            
            logger.log(logging.INFO, "Authenticated encryption version of the topic name 'choiceToken': " + topicNameEncryptedHex)
            logger.log(logging.INFO, b'Payload contains the topic name for which a choice token is asked: '+ topicWanted)
            logger.log(logging.INFO, b'Authenticated encryption version of the payload: ' + payloadByte)




            obj1 = client.publish(topicNameEncryptedHex, payloadByte , qos = qos, retain = retainFlag, msgid =msgid)
            print("msgid", obj1.mid)
            print("retain", retainFlag)
            print("retain")
            #logger.log(logging.INFO, retainFlag)
            #print("----Publish was sent to 'choiceToken' topic (step 2 of choice token schema)----")
            logger.log(logging.INFO, "----Publish was sent to 'choiceToken' topic (step 2 of choice token schema)----")
            self.choice_state_dict[topicname1x] = 1

        except Exception as e3:
               #print("ERROR %r ", e3.args)
               logger.log(logging.INFO, "ERROR %r ", e3.args)



    def subscribe_encrypted_clientID(self, client: mqtt, id_client):

        def on_message(client, userdata, msg):
           
            logger.log(logging.INFO, "----Publish message was received from broker (step 4 of choice token schema)---- from topic: " + msg.topic )
          
            data = msg.payload
            data_len = data[0:2]
            actual_data = data[2:]
         
            logger.log(logging.INFO, b'Encrypted data: '+ actual_data )

            backend = default_backend()
            decryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).decryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).unpadder()
            decrypted_data = decryptor.update(actual_data)
            unpadded = padder.update(decrypted_data) + padder.finalize()
            logger.log(logging.INFO, b'Decrypted data: '+ unpadded )


            indexMAC = unpadded.rfind(b'::::')
            topic_and_choiceTokens = unpadded[0:indexMAC]
            mac_of_choice_token = unpadded[indexMAC+4:]
            #print("mac_of_choice_token", mac_of_choice_token)
            #print("topic_and_choiceTokens", topic_and_choiceTokens)



            index1 = topic_and_choiceTokens.index(b'::::')
            topicName = topic_and_choiceTokens[0:index1]
            choiceToken = topic_and_choiceTokens[index1+4:]

            to_check = bytes(self.id_client, 'utf-8') + b'::::signVerifyFailed'

            #bilgesu: modification
            if topic_and_choiceTokens == to_check:
                self.fail_to_verify_mac = True
                logger.log(logging.ERROR, "Received signVerifyFailed from broker, wont get choicetoken.")





            else:
                #print("choiceToken: ", choiceToken)
                #print("Topic name:", topicName, " and its choiceToken: ", choiceToken.hex())
                print("msg.qos + msg.retain + msg.mid: ", msg.qos , msg.retain , msg.mid)
                if msg.retain == 0:
                    retainFlag = False
                else:
                    retainFlag = False
                message_str = str(msg.qos) + str(retainFlag) + str(msg.mid)
                message_bytes = topic_and_choiceTokens + force_bytes(message_str)
                print("message_bytes: ", message_bytes)

                logger.log(logging.INFO, b'Topic name: '+ topicName )
                logger.log(logging.INFO, "Its choiceToken: " + choiceToken.hex())
                h = hmac.HMAC(self.session_key, hashes.SHA256())
                h.update(message_bytes)
                signature = h.finalize()

                #print("Received MAC of the payload: ", mac_of_choice_token )
                #print("Calculated MAC of the payload: ", signature )
                logger.log(logging.INFO, b'Received MAC of the payload: '+ mac_of_choice_token )
                logger.log(logging.INFO, b'Calculated MAC of the payload: '+ signature )

                if(mac_of_choice_token == signature):
                    #print("The content of the message has not been changed. Mac is correct ")
                    logger.log(logging.INFO, "The content of the message has not been changed. Mac is correct ")
                    topicName_str = bytes.decode(topicName)

                    #print("choicetoken 367: ", choiceToken)

                    choiceTokenHex = choiceToken.hex()

                    #print("choicetokenhex  371:", choiceTokenHex)


                    self.choiceTokenDictionary[topicName_str] = choiceTokenHex
                    #print(self.choiceTokenDictionary)
                    self.choice_state_dict[topicName_str] = 2
                else:
                    #print("The content of the message has been changed. Mac is not correct")
                    logger.log(logging.INFO, "The content of the message has been changed. Mac is not correct")

        client.on_message = on_message

        if (self.choice_token_state == 0):



            #mac_message = message +
            msgid = self._mid_generate()
            print("before msgid sub", msgid)
            qos = 1
            message_str = self.id_client + str(qos) + str(msgid)
            print("message_str: ", message_str)
            message_hash = bytes(message_str, 'utf-8')

            message = bytes(self.id_client, 'utf-8')
            print("message :", message)

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message_hash)
            signature = h.finalize()

            topicName = message + b'::::' + signature

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(topicName) + padder.finalize()
            topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
            topicNameEncryptedHex = topicNameEncryptedByte.hex()

            client.subscribe(topicNameEncryptedHex, qos= qos, msgid = msgid)
            #print("----Client was subscribed to its encrypted clientID (step 1 of the choice token schema)")
            #print("Authenticated Encryption version of the clientID: ", topicNameEncryptedHex )
            logger.log(logging.INFO, "----Client was subscribed to its encrypted clientID (step 1 of the choice token schema)")
            logger.log(logging.INFO,"Authenticated Encryption version of the clientID: " + topicNameEncryptedHex )
            self.choice_token_state = 1

        return client



    def subscribe_real_topics(self, client: mqtt, topicname):
        def on_message(client, userdata, msg):
            #print("----Publish message was received from broker")
            logger.log(logging.INFO, "----Publish message was received from broker")
            data = msg.payload
            actual_data = data[2:]
            #print("Encrypted topic: " ,msg.topic )
            #print(f"Encrypted payload: `{actual_data}`")
            logger.log(logging.INFO, b'Encrypted topic: ' + msg.topic )
            logger.log(logging.INFO, b'Encrypted payload: ' + actual_data)
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
            #print("Choice token from dictionary:",self.choiceTokenDictionary[topic_name_str])
            #print("Topic name from dictionary:",topic_name_str)
            #print("Decrypted topic name: ", topic_name_str ," and its mac: ", mac_of_topic_name)
            #print("Choice token of the topic: ", choiceTokenhex )
            logger.log(logging.INFO, b'Decrypted topic name: ' + topic_name + b' and its mac: ' + mac_of_topic_name)
            logger.log(logging.INFO, "Choice token of the topic: "+ choiceTokenhex )

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(topic_name)
            signature = h.finalize()

            if(signature == mac_of_topic_name):
                #print("The content of the topic name is not changed. Mac of the topic name is correct")
                logger.log(logging.INFO, "The content of the topic name is not changed. Mac of the topic name is correct")

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
                #print("Message after decryption with session key: ", message_encrypted_with_ct)
                logger.log(logging.INFO, b'Message after decryption with session key: '+ message_encrypted_with_ct)

                choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
                #print("Choicetoken key: ", choicetoken_key)

                decryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).decryptor()
                padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).unpadder()
                decrypted_data2 = decryptor.update(message_encrypted_with_ct)
                unpadded_message = padder.update(decrypted_data2) + padder.finalize()
                #print("Message after decryption with choice token: ", unpadded_message, " from topic: ",  topic_name_str )
                logger.log(logging.INFO, b'Message after decryption with choice token: '+ unpadded_message)
                logger.log(logging.INFO, "Topic name: "+  topic_name_str)

                if msg.retain == 0:
                    retainFlag = False
                else:
                    retainFlag = True

                message_hash_str = str(msg.qos) + str(retainFlag) + str(msg.mid)
                message_bytes_hash = message_encrypted_with_ct + force_bytes(message_hash_str)
                print("message_hash_str ", message_hash_str)
                print("message_bytes_hash ", message_bytes_hash)

                h = hmac.HMAC(self.session_key, hashes.SHA256())
                h.update(message_bytes_hash)
                signature = h.finalize()


                if(signature == mac_of_payload):
                    #print("The content of the payload is not changed, Mac of the payload is correct")
                    logger.log(logging.ERROR, "The content of the payload is not changed, Mac of the payload is correct")
                    #print("MESSAGE: " ,unpadded_message, "FROM ", topic_namepub )

                else:
                    #print("The content of the payload is changed, Mac of the payload is not correct")
                    logger.log(logging.ERROR, "The content of the payload is changed, Mac of the payload is not correct")

            else:
                #print("The content of the topic name is changed")
                logger.log(logging.ERROR, "The content of the topic name is changed")



        if(self.choice_state_dict[topicname] == 2):

            client.on_message = on_message
            #print("----Function to subscribe to topic: ", topicname )
            logger.log(logging.INFO, "----Function to subscribe to topic: "+ topicname )
            topicName_byte = force_bytes(topicname)
            msgid = self._mid_generate()
            print("before msgid sub", msgid)
            qos = 1

            topicname_str = topicname + str(qos) + str(msgid)
            #topicname_str = topicname + str(qos)     #for error cases. broker.py'deki 785.satıra gidiyor
            hash_bytes = force_bytes(topicname_str)

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(hash_bytes)
            signature = h.finalize()
            #print("MAC of the topic: ", signature )
            logger.log(logging.INFO, b'MAC of the topic: '+ signature )


            topicName_subscribe = topicName_byte + b'::::' + signature

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(topicName_subscribe) + padder.finalize()
            topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
            topicNameEncryptedHex = topicNameEncryptedByte.hex()
            #print("Authenticated encryption version of the topic:" ,topicNameEncryptedHex )
            logger.log(logging.INFO, "Authenticated encryption version of the topic:" + topicNameEncryptedHex )

           
            client.subscribe(topicNameEncryptedHex, qos=qos, msgid = msgid)
            #print("Subscribed to: " ,topicNameEncryptedHex )
            logger.log(logging.INFO, "Subscribed to: " + topicNameEncryptedHex )
            self.choice_state_dict[topicname] = 3


            self.subscribe_success.append(topicname)


        return client


    async def receive_message_after_unsub(self, client:Client):
        logger.log(logging.INFO, "In receive messag after unsub.")

        def on_unsubscribe(self, obj, mid):

            packet_bytes = client.get_packet_bytes()
            logger.log(logging.INFO, "Unsuback was received, message Id: " + str(mid))

            #logger.log(logging.ERROR, "mac " + str(packet_bytes))

            index1 = packet_bytes.index(b'::::')
            mac_real =  packet_bytes[index1+4:]

            #logger.log(logging.ERROR, "mac " + str(mac_real))

            byte_packet_id = force_bytes(str(mid), 'utf-8')
            message = byte_packet_id 
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()

            #logger.log(logging.ERROR, "mac " + str(signature))

            if (mac_real == signature):
                logger.log(logging.INFO, "Signature of UNSUBACK is verified.")
                self.unverified_unsuback_topics_list.append(True)
            else:
                logger.log(logging.ERROR, "Signature of UNSUBACK is not verified. Please try again to unsubscribe from the topic(s).")
                self.unsuback_verified = False
                self.unverified_unsuback_topics_list.append(False)

        self.on_unsubscribe = on_unsubscribe


    def subscribe4(self, client: mqtt, is_after_publish:bool, is_unsub:bool):
        def on_message(client, userdata, msg):
            #print("----Publish message was received from broker")
            #print(f"Encrypted payload: `{msg.payload}` from  encrypted topic: `{msg.topic}` ")
            logger.log(logging.WARNING, "----Publish message was received from broker")
            logger.log(logging.INFO, b'Encrypted payload: ' + msg.payload)
            logger.log(logging.INFO, "Encrypted topic: " + msg.topic )

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

            if topic_name_str == self.id_client: #receiving bad mac here.
                

                data = msg.payload
                data_len = data[0:2]
                actual_data = data[2:]

                decryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).decryptor()
                padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).unpadder()
                decrypted_data = decryptor.update(actual_data)
                unpadded = padder.update(decrypted_data) + padder.finalize()

                logger.log(logging.INFO, b'769 payload received , unpadded= ' + unpadded)
                index1 = unpadded.index(b'::::')    #this added at 2 may - burcu
                piece_1 = unpadded[0:index1]
                piece_2 = unpadded[index1+4:]

                index2 = piece_2.index(b'::::')

                message_received = piece_2[0:index2]
                mac_replacer = piece_2[index2+4:]
                

                if piece_1 == bytes(self.id_client, 'utf-8') and message_received == b'signVerifyFailed':

                    self.fail_to_verify_mac = True
                    if is_after_publish:
                        logger.log(logging.ERROR, "Received bad MAC, your published message won't be relayed to the subscribers.")
                        print("Received bad MAC, your published message won't be relayed to the subscribers.")
                    else:
                        if is_unsub:

                            self.received_badmac_unsub = True
                            logger.log(logging.ERROR, "Received bad MAC, unsubscribe request failed.")
                            print("Received bad MAC, unsubscribe request failed.")
                        else:
                            logger.log(logging.ERROR, "Received bac MAC")
                            print("Received bac MAC")
                
                elif piece_1 == b'wildcardChoiceToken':
                    logger.log(logging.WARNING, "wildcardChoiceToken")
                    piece_2 = unpadded[index1+4:]
                    index2 = piece_2.index(b'::::')
                    piece_topic = piece_2[0:index2]
                    piece_3 = piece_2[index2+4:]
                    index3 = piece_3.index(b'::::')
                    piece_choiceToken = piece_3[0:index3]
                    piece_mac = piece_3[index3+4:]
                    piece_topic = force_str(piece_topic)
                    piece_choiceToken = piece_choiceToken.hex()

                    self.choiceTokenDictionary[piece_topic] = piece_choiceToken
                   
                    logger.log(logging.WARNING, "Topic name from dictionary: " + piece_topic)
                    logger.log(logging.WARNING, "Choice token from dictionary: " + piece_choiceToken)


            else:

                value = self.choiceTokenDictionary.get(topic_name_str,None)
                if  (value == None):
                    logger.log(logging.ERROR, "no choice token for topic: " +topic_name_str)
                    return client

                choiceTokenhex = self.choiceTokenDictionary[topic_name_str]
                choiceToken = unhexlify(choiceTokenhex)
                #print("Choice token from dictionary:",self.choiceTokenDictionary[topic_name_str])
                #print("Topic name from dictionary:",topic_name_str)


                h = hmac.HMAC(self.session_key, hashes.SHA256())
                h.update(topic_name)
                signature = h.finalize()
                #print("Received MAC of topic name: ", mac_of_topic_name)
                #print("Calculated MAC of topic name: ", signature )
                logger.log(logging.INFO, b'Received MAC of topic name: '+ mac_of_topic_name)
                logger.log(logging.INFO, b'Calculated MAC of topic name: '+ signature )

                if(signature == mac_of_topic_name):
                    #print("The content of the topic name is not changed. Mac of the topic name is correct")
                    #print("Decrypted topic name: ", topic_name_str)
                    #print("Choice token of the topic: ", choiceTokenhex )
                    logger.log(logging.INFO, "The content of the topic name is not changed. Mac of the topic name is correct")
                    logger.log(logging.WARNING, "Decrypted topic name: "+ topic_name_str)
                    logger.log(logging.INFO, "Choice token of the topic: "+ choiceTokenhex )

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
                    #print("Message after decryption with session key: ", message_encrypted_with_ct)
                    logger.log(logging.INFO, b'Message after decryption with session key: '+ message_encrypted_with_ct)
                    choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
                    #print("choicetoken_key ", choicetoken_key)

                    decryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).decryptor()
                    padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).unpadder()
                    decrypted_data2 = decryptor.update(message_encrypted_with_ct)
                    unpadded_message = padder.update(decrypted_data2) + padder.finalize()
                    #print("Message after decryption with choice token: ", unpadded_message, " from ", topic_name_str)

                    if msg.retain == 0:
                        retainFlag = False
                    else:
                        retainFlag = True

                    message_hash_str = str(msg.qos) + str(retainFlag) + str(msg.mid)
                    message_bytes_hash = message_encrypted_with_ct + force_bytes(message_hash_str)
                    print("message_hash_str ", message_hash_str)
                    print("message_bytes_hash ", message_bytes_hash)

                    h = hmac.HMAC(self.session_key, hashes.SHA256())
                    h.update(message_bytes_hash)
                    signature = h.finalize()
                    #print("Received MAC of payload: ", mac_of_payload)
                    #print("Calculated MAC of payload: ", signature )
                    logger.log(logging.INFO, b'Received MAC of payload: '+ mac_of_payload)
                    logger.log(logging.INFO, b'Calculated MAC of payload: '+ signature )

                    if(signature == mac_of_payload):
                        #print("The content of the payload is not changed. Mac of the payload is correct")
                        #print("Message after decryption with choice token: ", unpadded_message, " from ", topic_name_str)
                        logger.log(logging.INFO, "The content of the payload is not changed. Mac of the payload is correct")
                        logger.log(logging.WARNING, b'Message after decryption with choice token: '+ unpadded_message)
                        #print("MESSAGE: " ,unpadded_message, "FROM ", topic_name )



                    else:
                        #print("The content of the payload is changed, Mac of the payload is not correct")
                        logger.log(logging.ERROR, "The content of the payload is changed, Mac of the payload is not correct")


                else:
                    #print("The content of the topic name is changed. Mac of the topic name is correct")
                    logger.log(logging.INFO, "The content of the topic name is not changed. Mac of the topic name is correct")




        client.on_message = on_message



    async def subscribe_clientID(self, client: mqtt, id_client):
        def on_message(client, userdata, msg):
            if (self.key_establishment_state == 3):
                #print("----Publish message was received from broker (step 5 of the DH)---- from " , msg.topic , " topic")
                logger.log(logging.INFO, "----Publish message was received from broker (step 5 of the DH)---- from " + msg.topic + " topic")
                data = msg.payload

                data_len = data[0:2]
                actual_data = data[2:]
                index1 = actual_data.index(b'::::')

                broker_x509_pem = actual_data[0:index1]
                nonce_pub_and_sign = actual_data[index1+4:]


                index2 = nonce_pub_and_sign.index(b'::::')
                broker_dh_public_key = nonce_pub_and_sign[0:index2]
                byt = bytes(broker_dh_public_key)
                str = byt.hex()
                #print(type(str))

                nonce_rsa_sign = nonce_pub_and_sign[index2 + 4 :]

                index3 = nonce_rsa_sign.index(b'::::')
                nonce_1 = nonce_rsa_sign[0:index3]
                self.nonce1 = nonce_1

                broker_rsa_sign = nonce_rsa_sign[index3+4:]
               
                logger.log(logging.INFO, "PAYLOAD COMING FROM BROKER FOR STEP 5:")
                logger.log(logging.INFO, b'BROKER X509 CERTIFICATE: ' + broker_x509_pem)
                logger.log(logging.INFO, b'BROKER DIFFIE HELLMAN PUBLIC KEY IN HEX FORMAT:'+ broker_dh_public_key)
                logger.log(logging.INFO, b'NONCE_1 IN HEX FORMAT: '+ nonce_1)
                logger.log(logging.INFO, b'BROKER RSA SIGN IN HEX FORMAT: '+ broker_rsa_sign)
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

              
                logger.log(logging.INFO, b'BROKER X509 PUBLIC KEY:' + broker_x509_public_key_pem)

                client_ID_byte = bytes(self.id_client, 'UTF-8')
                message = broker_dh_public_key + b'::::' + self.nonce1 + b'::::' + client_ID_byte
                #message = broker_dh_public_key + b'::::' + self.nonce1 + b'::::'    #for error cases
                message_bytes = bytes(message)
                broker_rsa_sign_bytes = bytes(broker_rsa_sign)



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
                    #print("MESSAGE VERIFIED")
                    logger.log(logging.INFO, "MESSAGE VERIFIED")
                    self.verified = True

                except:
                    #print("MESSAGE NOT VERIFIED")
                    logger.log(logging.ERROR, "MESSAGE NOT VERIFIED")
                    self.disconnect_flag = True
                    self.disconnect()


            elif (self.key_establishment_state == 7):
                #print("----Publish message was received from broker (step 8 of the DH)----")
                logger.log(logging.INFO, "----Publish message was received from broker (step 8 of the DH)----")

                data = msg.payload
                data_len = data[0:2]
                actual_data = data[2:]
                if (actual_data == force_bytes(self.id_client) + b'::::' +  b'notAuthenticated'):
                    #print("Broker disconnect you due to nonce verification error")
                    logger.log(logging.INFO, "1137 Broker disconnects you due to nonce verification error")
                    #not auth received from broker
                    self._dontreconnect = True
                    return client
                    
                backend = default_backend()

                #print(f"ALL DATA `{actual_data}` from `{msg.topic}` topic")
                #logger.log(logging.INFO, "ALL DATA "+ actual_data.hex() +" from "+ msg.topic + " topic")
                data = msg.payload
                data_len = data[0:2]
                actual_data = data[2:]
                #print("SESSION KEY: ", )


                decryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).decryptor()
                padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).unpadder()

                decrypted_data = decryptor.update(actual_data)

                unpadded = padder.update(decrypted_data) + padder.finalize()

                #print("Decrypted message: ", unpadded)
                logger.log(logging.INFO, b'Decrypted message: '+ unpadded)


                index1 = unpadded.index(b'::::')
                comming_nonce2_or_clientId = unpadded[0:index1]
                comming_client_id_orNotAuth = unpadded[index1+4:]


                if(bytes.decode(comming_nonce2_or_clientId,"utf-8") == self.id_client and comming_client_id_orNotAuth == b'notAuthenticated'):
                    #print("Broker disconnect you due to RSA or nonce verification error")
                    logger.log(logging.INFO, "Broker disconnects you due nonce verification error at DH step 8")

                    #not auth received from broker

                    self._dontreconnect = True
                    self.disconnect_flag = True

                    self.disconnect()




                else:
                    self.nonce2 = comming_nonce2_or_clientId #set nonce2
                    self.comming_client_id = comming_client_id_orNotAuth

                    #print("Nonce 2 received:", comming_nonce2_or_clientId)
                    #print("Client ID received:", comming_client_id_orNotAuth)
                    logger.log(logging.INFO, b'Nonce 2 received: ' + comming_nonce2_or_clientId)

                    logger.log(logging.INFO, b'Client ID received: ' + comming_client_id_orNotAuth)

                    #print(self.id_client)



            elif (self.key_establishment_state == 10):
                #print("----Publish message was received from broker (step 10 of the DH)----")
                logger.log(logging.INFO, "----Publish message was received from broker (step 10 of the DH)----")


                data = msg.payload

                data_len = data[0:2]
                actual_data = data[2:]

                #print("Data without length:", actual_data)
                #print(f"ALL DATA `{actual_data}` from `{msg.topic}` topic")
                #logger.log(logging.INFO, "MESSAGE: " + actual_data + " from " + msg.topic + " topic")
                backend = default_backend()
                decryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).decryptor()
                padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).unpadder()


                decrypted_data = decryptor.update(actual_data)
                unpadded = padder.update(decrypted_data) + padder.finalize()

                #print("Decrypted message: ", unpadded)
                logger.log(logging.INFO, b'Decrypted message: ' + unpadded)


                index1 = unpadded.index(b'::::')
                comming_nonce3 = unpadded[0:index1]
                #comming_nonce3 = unpadded[0:]    #error case
                comming_client_id = unpadded[index1+4:]


                #print("Received Nonce 3: ", comming_nonce3, "and Nonce 3 sent before: ", force_bytes(self.nonce3) )

                logger.log(logging.INFO, b'Received Nonce 3: '+ comming_nonce3+ b'and Nonce 3 sent before: '+ force_bytes(self.nonce3) )

                if(bytes.decode(comming_nonce3,"utf-8") == self.id_client and comming_client_id == b'notAuthenticated'):
                    #print("Broker disconnect you due to nonce verification error at step 9")
                    logger.log(logging.INFO, "Broker disconnect you due to nonce verification error at step 9")
                    #not auth received from broker

                    self._dontreconnect = True
                    #self.disconnect()
                    #self.disconnect_flag = True



                else:
                    if comming_nonce3 == force_bytes(self.nonce3) and comming_client_id == force_bytes(self.id_client):
                        #print("Received nonce 3 and sent nonce 3 are the same")
                        #print("BROKER IS AUTHENTICATED")
                        logger.log(logging.INFO, "Received nonce 3 and sent nonce 3 are the same")
                        logger.log(logging.INFO, "BROKER IS AUTHENTICATED")

                        

                        self.authenticated = True
                        self._authenticated = True


                        logger.log(logging.INFO, "SELF.AUTH IS TRUE NOW")

                    else:
                        #print("Received nonce 3 and sent nonce 3 are not the same")
                        #print("BROKER CANNOT BE AUTHENTICATED")
                        logger.log(logging.INFO, "Received nonce 3 and sent nonce 3 are not the same")
                        logger.log(logging.INFO, "BROKER CANNOT BE AUTHENTICATED")
                        self.disconnect_flag = True
                        self.disconnect()


            else:

                message = msg.payload
                if message == self.id_client:
                    #print("Key establishment failed. Disconnect, do not reconnect untill establishing a new connection with a new key establishment state.")
                    logger.log(logging.INFO, "Key establishment failed. Disconnect, do not reconnect untill establishing a new connection with a new key establishment state.")
                    self._dontreconnect = True #variable set to true to prevent reconnect in this session.
                #print(f"ALL DATA `{msg.payload}` from `{msg.topic}` topic")
                #print("something went wrong")
                #logger.log(logging.INFO, "ALL DATA " + msg.payload + " from " + msg.topic + " topic")
                logger.log(logging.INFO, "something went wrong")


        client.on_message = on_message

        if (self.key_establishment_state == 2):
            client.subscribe(id_client, 1)
            #print("----Client subscribed to its client id (step 3 of the DH Key Exchange)----")
            logger.log(logging.INFO, "----Client subscribed to its client id (step 3 of the DH Key Exchange)----")
            self.key_establishment_state = 3


        return client
    

    def encrypt_mac_one_topic_name(self, topic):

        topic_name = topic
        qos = str(1) #kontrol et
        to_be_hashed = bytes(topic, 'utf-8') + b'::::' + bytes(qos, 'utf-8')
        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(to_be_hashed)
        hash_to_append = h.finalize()

        to_be_encrypted = bytes(topic_name, 'utf-8') + b'::::' + hash_to_append
        #to_be_encrypted = to_be_encrypted + b'broke it' #wrong mac on purpose

        backend = default_backend()
        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(to_be_encrypted) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_hex = encrypted.hex()

        #enrypted_hex: ae(ks, topic||mac(ks, topic||qos)) format
    
        return encrypted_hex
    
  



    async def encrypt_mac_topic_names(self, list_topics):

        return_list = []

        for topic in list_topics:

            topic_name = topic
            qos = str(1) #kontrol et
            to_be_hashed = bytes(topic, 'utf-8') + b'::::' + bytes(qos, 'utf-8')
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(to_be_hashed)
            hash_to_append = h.finalize()

            to_be_encrypted = bytes(topic_name, 'utf-8') + b'::::' + hash_to_append
            #to_be_encrypted = to_be_encrypted + b'broke it' #wrong mac on purpose

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(to_be_encrypted) + padder.finalize()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_hex = encrypted.hex()

            #enrypted_hex: ae(ks, topic||mac(ks, topic||qos)) format
            return_list.append(encrypted_hex)

        return return_list
    

    def subscribe_for_topic_hashing(self, client: mqtt, topicname):
        def on_message(client, userdata, msg):
            #print("----Publish message was received from broker")
            logger.log(logging.INFO, "----Publish message was received from broker")
            data = msg.payload
            actual_data = data[2:]
            #print("Encrypted topic: " ,msg.topic )
            #print(f"Encrypted payload: `{actual_data}`")
            logger.log(logging.INFO, "Encrypted topic: " + msg.topic )
            logger.log(logging.INFO, b'Encrypted payload: ' + actual_data)
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
            #print("Choice token from dictionary:",self.choiceTokenDictionary[topic_name_str])
            #print("Topic name from dictionary:",topic_name_str)
            #print("Decrypted topic name: ", topic_name_str ," and its mac: ", mac_of_topic_name)
            #print("Choice token of the topic: ", choiceTokenhex )
            logger.log(logging.INFO, b'Decrypted topic name: ' + topic_name + b' and its mac: ' + mac_of_topic_name)
            logger.log(logging.INFO, "Choice token of the topic: "+ choiceTokenhex )

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(topic_name)
            signature = h.finalize()

            if(signature == mac_of_topic_name):
                #print("The content of the topic name is not changed. Mac of the topic name is correct")
                logger.log(logging.INFO, "The content of the topic name is not changed. Mac of the topic name is correct")

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
                #print("Message after decryption with session key: ", message_encrypted_with_ct)
                logger.log(logging.INFO, b'Message after decryption with session key: '+ message_encrypted_with_ct)

                choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
                #print("Choicetoken key: ", choicetoken_key)

                decryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).decryptor()
                padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).unpadder()
                decrypted_data2 = decryptor.update(message_encrypted_with_ct)
                unpadded_message = padder.update(decrypted_data2) + padder.finalize()
                #print("Message after decryption with choice token: ", unpadded_message, " from topic: ",  topic_name_str )
                logger.log(logging.INFO, b'Message after decryption with choice token: '+ unpadded_message)
                logger.log(logging.INFO, "Topic name: "+  topic_name_str)

                if msg.retain == 0:
                    retainFlag = False
                else:
                    retainFlag = True

                message_hash_str = str(msg.qos) + str(retainFlag) + str(msg.mid)
                message_bytes_hash = message_encrypted_with_ct + force_bytes(message_hash_str)
                print("message_hash_str ", message_hash_str)
                print("message_bytes_hash ", message_bytes_hash)

                h = hmac.HMAC(self.session_key, hashes.SHA256())
                h.update(message_bytes_hash)
                signature = h.finalize()


                if(signature == mac_of_payload):
                    #print("The content of the payload is not changed, Mac of the payload is correct")
                    logger.log(logging.INFO, "The content of the payload is not changed, Mac of the payload is correct")
                    #print("MESSAGE: " ,unpadded_message, "FROM ", topic_namepub )

                else:
                    #print("The content of the payload is changed, Mac of the payload is not correct")
                    logger.log(logging.INFO, "The content of the payload is changed, Mac of the payload is not correct")

            else:
                #print("The content of the topic name is changed")
                logger.log(logging.INFO, "The content of the topic name is changed")


        client.on_message = on_message
        if(self.choice_state_dict[topicname] == 2):

            
            logger.log(logging.INFO, "----Function to subscribe to topic: "+ topicname )
            topicName_byte = force_bytes(topicname)
            msgid = self._mid_generate()
            print("before msgid sub", msgid)
            qos = 1

            topicname_str = topicname + str(qos) + str(msgid)
            hash_bytes = force_bytes(topicname_str)

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(hash_bytes)
            signature = h.finalize()
            #print("MAC of the topic: ", signature )
            logger.log(logging.INFO, b'MAC of the topic: '+ signature )


            topicName_subscribe = topicName_byte + b'::::' + signature

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(topicName_subscribe) + padder.finalize()
            topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
            topicNameEncryptedHex = topicNameEncryptedByte.hex()
            #print("Authenticated encryption version of the topic:" ,topicNameEncryptedHex )
            logger.log(logging.INFO, "Authenticated encryption version of the topic:" + topicNameEncryptedHex )

            client.subscribe(topicNameEncryptedHex, qos=qos, msgid = msgid)
            #print("Subscribed to: " ,topicNameEncryptedHex )
            logger.log(logging.INFO, "Subscribed to: " + topicNameEncryptedHex )
            self.choice_state_dict[topicname] = 3


            self.subscribe_success.append(topicname)


        return client
    

    def publish_to_topichashing_clientID(self, client: mqtt, topicName):    #used by subscriber
           
        def on_publish(client, obj, mid):
            #print("Puback was received, messageID =",str(mid))
            logger.log(logging.INFO, "Puback was received, messageID =" + str(mid))
            puback = self.get_puback()

            #logger.log(logging.ERROR, "mac " + str(puback))

            index1 = puback.index(b'::::')
            mac_real =  puback[index1+4:]

            #logger.log(logging.ERROR, "mac " + str(mac_real))

            byte_packet_id = force_bytes(str(mid), 'utf-8')
            message = byte_packet_id 
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()

            #logger.log(logging.ERROR, "mac " + str(signature))

            if mac_real == signature:
                logger.log(logging.INFO, "Signature of PUBACK is verified.")
            else:
                logger.log(logging.ERROR, "Signature of PUBACK is not verified.")


        client.on_publish = on_publish
        #print("----Function to publish to topic: ", topicName )
        #print("Message to be published: ", message)
        logger.log(logging.INFO, "----Function to publish to topic: " + topicName )
        message = str(self._client_id)

        topicName_byte = force_bytes(topicName)
        choiceTokenhex = self.choiceTokenDictionary[topicName]
        choiceToken = unhexlify(choiceTokenhex)
    


        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(topicName_byte)
        signature = h.finalize()
        #signature = b'broken'

        topic_publish = topicName_byte + b'::::' + signature

        backend = default_backend()
        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(topic_publish) + padder.finalize()
        encrypted_topic = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_topic_hex = encrypted_topic.hex()
        #print("Authenticated encryption version of the topic name to be published: ", encrypted_topic_hex)
        logger.log(logging.INFO, "Authenticated encryption version of the topic name to be published: " + encrypted_topic_hex)

        message_byte = force_bytes(message)

        choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
        #print("245 choiceTokenKEY: ", choicetoken_key)



        encryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).padder()
        padded_data = padder.update(message_byte) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_message_byte = force_bytes(encrypted_message)
        #print("Message after encryption with the choice token: ", encrypted_message)
        logger.log(logging.INFO, b'Message after encryption with the choice token: '+ encrypted_message)

        qos = 1
        retainFlag = False
        msgid = self._mid_generate()
        hash_message_str = str(qos) + str(retainFlag) + str(msgid)
        hash_message_bytes = encrypted_message_byte + force_bytes(hash_message_str)


        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(hash_message_bytes)
        signature2 = h.finalize()

        message_publish = encrypted_message_byte + b'::::' + signature2


        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(message_publish) + padder.finalize()
        encrypted_message2 = encryptor.update(padded_data) + encryptor.finalize()
        #print("Message after authenticated encyption with the session key: ", encrypted_message2)
        logger.log(logging.INFO, b'Message after authenticated encyption with the session key: '+ encrypted_message2)

        client.publish(encrypted_topic_hex, encrypted_message2 , qos = qos, retain = retainFlag, msgid=msgid)
        self.subscribe_success_topic_hash = 1


        return client
    
    def subscribe_to_topicHashing_publisher(self, client: mqtt, topicname):
        def on_message(client, userdata, msg):
            #print("----Publish message was received from broker")
            logger.log(logging.INFO, "---- 1536 Publish message was received from broker")
            data = msg.payload
            actual_data = data[2:]
            logger.log(logging.INFO, "Encrypted topic: " + msg.topic )
            logger.log(logging.INFO, b'Encrypted payload: ' + actual_data)
            topic_hex = msg.topic
            topic_byte = unhexlify(topic_hex)
            backend = default_backend()
            decryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).decryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).unpadder()
            decrypted_data = decryptor.update(topic_byte)
            unpadded = padder.update(decrypted_data) + padder.finalize()
            logger.log(logging.INFO, b'Decrypted payload: ' + unpadded)
            if(self.subscribe_success_topic_hash == 2):
                self.topic_hashing_clear = True

                #initialize the dictionaries
                self.seed_dictionary = {}
                self.count_dictionary = {}
                self.topic_hash_dictionary = {} 
                self.hash_topic_dictionary = {}
                self.topic_subscribe_boolean = {}

                index1 = unpadded.index(b'::::')
                topic_name = unpadded[0:index1]
                mac_of_topic_name = unpadded[index1+4:]

                topic_name_str = bytes.decode(topic_name)
                choiceTokenhex = self.choiceTokenDictionary[topic_name_str]
                choiceToken = unhexlify(choiceTokenhex)
                #print("Choice token from dictionary:",self.choiceTokenDictionary[topic_name_str])
                #print("Topic name from dictionary:",topic_name_str)
                #print("Decrypted topic name: ", topic_name_str ," and its mac: ", mac_of_topic_name)
                #print("Choice token of the topic: ", choiceTokenhex )
                logger.log(logging.INFO, b'Decrypted topic name: ' + topic_name + b' and its mac: ' + mac_of_topic_name)
                logger.log(logging.INFO, "Choice token of the topic: "+ choiceTokenhex )

                h = hmac.HMAC(self.session_key, hashes.SHA256())
                h.update(topic_name)
                signature = h.finalize()

                if(signature == mac_of_topic_name):
                    #print("The content of the topic name is not changed. Mac of the topic name is correct")
                    logger.log(logging.INFO, "The content of the topic name is not changed. Mac of the topic name is correct")

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
                    #print("Message after decryption with session key: ", message_encrypted_with_ct)
                    logger.log(logging.INFO, b'Message after decryption with session key: '+ message_encrypted_with_ct)

                    choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
                    #print("Choicetoken key: ", choicetoken_key)

                    decryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).decryptor()
                    padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).unpadder()
                    decrypted_data2 = decryptor.update(message_encrypted_with_ct)
                    unpadded_message = padder.update(decrypted_data2) + padder.finalize()
                    #print("Message after decryption with choice token: ", unpadded_message, " from topic: ",  topic_name_str )
                    logger.log(logging.INFO, "Topic name: "+  topic_name_str)

                    if msg.retain == 0:
                        retainFlag = False
                    else:
                        retainFlag = True

                    message_hash_str = str(msg.qos) + str(retainFlag) + str(msg.mid)
                    message_bytes_hash = message_encrypted_with_ct + force_bytes(message_hash_str)
                    print("message_hash_str ", message_hash_str)
                    print("message_bytes_hash ", message_bytes_hash)

                    h = hmac.HMAC(self.session_key, hashes.SHA256())
                    h.update(message_bytes_hash)
                    signature = h.finalize()


                    if(signature == mac_of_payload):
                        #print("The content of the payload is not changed, Mac of the payload is correct")
                        logger.log(logging.INFO, "The content of the payload is not changed, Mac of the payload is correct")
                        #print("MESSAGE: " ,unpadded_message, "FROM ", topic_namepub )
                        logger.log(logging.INFO, b'Message after decryption with choice token: '+ unpadded_message)
                        index_of_polynomial = unpadded_message.rfind(b'::::')
                        topic_list = unpadded_message[0:index_of_polynomial]
                        polynomial = unpadded_message[index_of_polynomial+4:]
                        polynomial = bytes.decode(polynomial, 'utf-8')
                        logger.log(logging.INFO, "polynomial " + polynomial)
                        poly_list = polynomial.split(",")
                        #self.count +=1
                        
                        #salt_poly = self.polynomial_func(self.count,int(poly_list[0]),int(poly_list[1]),int(poly_list[2]),int(poly_list[3]))
                        #salt_poly = str(salt_poly)
                        #logger.log(logging.WARNING, "salt_poly: " + salt_poly + " and its count: " + str(self.count))
                        self.poly_list = poly_list
                        
                        topic_list = topic_list.split(b'::::')
                        
                        
                        for topic_seed_pair in topic_list:

                            index = topic_seed_pair.index(b'$$$$')
                            topicName = topic_seed_pair[0:index]
                            seed = topic_seed_pair[index+4:]
                            topic_name_str = force_str(topicName)
                            seed_str = force_str(seed)
                            self.seed_dictionary[topic_name_str] = seed_str
                            self.count_dictionary[topic_name_str] = 0
                            self.count_dictionary[topic_name_str] += 1
                            salt_poly = self.polynomial_func(self.count_dictionary[topic_name_str],int(poly_list[0]),int(poly_list[1]),int(poly_list[2]),int(poly_list[3]))
                            salt_poly = str(salt_poly)
                            logger.log(logging.WARNING, "salt_poly: " + salt_poly + " and its count: " + str(self.count_dictionary[topic_name_str]) + " and it topic name:" + topic_name_str )
                            
                            dk = hashlib.pbkdf2_hmac('sha512', seed_str.encode(), salt_poly.encode(), 100000)
                            dk2 = dk.hex()
                            dk2 = str(dk2)
                            self.topic_hash_dictionary[topic_name_str] = dk2 
                            self.hash_topic_dictionary[dk2] = topic_name_str
                            self.topic_subscribe_boolean[topic_name_str] = False
                            logger.log(logging.WARNING, "Topic names: " + topic_name_str + ", and its first hash value: " + dk2 )
                
                        
                    

                        for keys,values in self.publisher_topic_dictionary.items():
                            logger.log(logging.INFO, "Seed dictionary " + keys )
                            logger.log(logging.INFO, values )
                        

                            


                    else:
                        #print("The content of the payload is changed, Mac of the payload is not correct")
                        logger.log(logging.INFO, "The content of the payload is changed, Mac of the payload is not correct")
                        

                else:
                    #print("The content of the topic name is changed")
                    logger.log(logging.INFO, "The content of the topic name is changed")
                    

                

 
        client.on_message = on_message
        if(self.subscribe_success_topic_hash == 1):

            #print("----Function to subscribe to topic: ", topicname )
            logger.log(logging.INFO, "----Function to subscribe to topic: "+ topicname )
            topicName_byte = force_bytes(topicname)
            msgid = self._mid_generate()
            print("before msgid sub", msgid)
            qos = 1

            topicname_str = topicname + str(qos) + str(msgid)
            hash_bytes = force_bytes(topicname_str)

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(hash_bytes)
            signature = h.finalize()
            #print("MAC of the topic: ", signature )
            logger.log(logging.INFO, b'MAC of the topic: '+ signature )


            topicName_subscribe = topicName_byte + b'::::' + signature

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(topicName_subscribe) + padder.finalize()
            topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
            topicNameEncryptedHex = topicNameEncryptedByte.hex()
            #print("Authenticated encryption version of the topic:" ,topicNameEncryptedHex )
            logger.log(logging.INFO, "Authenticated encryption version of the topic:" + topicNameEncryptedHex )

            client.subscribe(topicNameEncryptedHex, qos=qos, msgid = msgid)
            #print("Subscribed to: " ,topicNameEncryptedHex )
            logger.log(logging.INFO, "Subscribed to: " + topicNameEncryptedHex )
            self.subscribe_success_topic_hash = 2

        


        return client
    
    def publish_seeds(self, client: mqtt, topicsListForSeeds):  #used by publisher

        def on_publish(client, obj, mid):
            #print("Puback was received, messageID =",str(mid))
            logger.log(logging.INFO, "Puback was received, messageID =" + str(mid))
            puback = self.get_puback()

            #logger.log(logging.ERROR, "mac " + str(puback))

            index1 = puback.index(b'::::')
            mac_real =  puback[index1+4:]

            #logger.log(logging.ERROR, "mac " + str(mac_real))

            byte_packet_id = force_bytes(str(mid), 'utf-8')
            message = byte_packet_id 
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()

            #logger.log(logging.ERROR, "mac " + str(signature))

            if mac_real == signature:
                logger.log(logging.INFO, "Signature of PUBACK is verified.")

            else:
                logger.log(logging.ERROR, "Signature of PUBACK is not verified.")
                



        client.on_publish = on_publish
        self.hash_session_end = False
        #print("----Function to publish to topic: ", topicName )
        #print("Message to be published: ", message)

        topicName = "topicHashing" 

        message = ""
        
        for topicNameforSeed in topicsListForSeeds:
            cryptogen = SystemRandom()
            seed = cryptogen.randrange(1000000000, 9999999999)
            message += topicNameforSeed + "$$$$" + str(seed) + "::::"
            self.publisher_seed_dictionary[topicNameforSeed] = str(seed)
            logger.log(logging.WARNING, "Topic and Seed Pair =" + topicNameforSeed + ": " + str(seed) )
        cryptogen = SystemRandom()
        poly = cryptogen.randrange(1000, 9999)
        digits = []
        n = poly
        while n > 0:
            digit = n % 10
            digits.append(digit)
            n //= 10
        logger.log(logging.WARNING, digits)
        message +=  str(digits[3]) + "," + str(digits[2]) + "," + str(digits[1]) + "," + str(digits[0])
        logger.log(logging.WARNING, "message =" + message )
        self.polynomials = []
        self.polynomials.append(digits[3])
        self.polynomials.append(digits[2])
        self.polynomials.append(digits[1])
        self.polynomials.append(digits[0])
        topicName_byte = force_bytes(topicName)
        choiceTokenhex = self.choiceTokenDictionary[topicName]
        choiceToken = unhexlify(choiceTokenhex)
    


        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(topicName_byte)
        signature = h.finalize()
        #signature = b'broken'

        topic_publish = topicName_byte + b'::::' + signature

        backend = default_backend()
        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(topic_publish) + padder.finalize()
        encrypted_topic = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_topic_hex = encrypted_topic.hex()
        #print("Authenticated encryption version of the topic name to be published: ", encrypted_topic_hex)
        logger.log(logging.INFO, "Authenticated encryption version of the topic name to be published: " + encrypted_topic_hex)

        message_byte = force_bytes(message)

        choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
        #print("245 choiceTokenKEY: ", choicetoken_key)



        encryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).padder()
        padded_data = padder.update(message_byte) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_message_byte = force_bytes(encrypted_message)
        #print("Message after encryption with the choice token: ", encrypted_message)
        logger.log(logging.INFO, b'Message after encryption with the choice token: '+ encrypted_message)

        qos = 1
        retainFlag = False
        msgid = self._mid_generate()
        hash_message_str = str(qos) + str(retainFlag) + str(msgid)
        hash_message_bytes = encrypted_message_byte + force_bytes(hash_message_str)


        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(hash_message_bytes)
        signature2 = h.finalize()

        message_publish = encrypted_message_byte + b'::::' + signature2


        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(message_publish) + padder.finalize()
        encrypted_message2 = encryptor.update(padded_data) + encryptor.finalize()
        #print("Message after authenticated encyption with the session key: ", encrypted_message2)
        logger.log(logging.INFO, b'Message after authenticated encyption with the session key: '+ encrypted_message2)

        client.publish(encrypted_topic_hex, encrypted_message2 , qos = qos, retain = retainFlag, msgid=msgid)
        
        self.count +=1
        salt_poly = self.polynomial_func(self.count,self.polynomials[0],self.polynomials[1],self.polynomials[2],self.polynomials[3])
        salt_poly = str(salt_poly)
        logger.log(logging.WARNING, "salt_poly: " + salt_poly + " and its count: " + str(self.count))
        for topicName, seed in self.publisher_seed_dictionary.items():
            dk = hashlib.pbkdf2_hmac('sha512', seed.encode(), salt_poly.encode(), 100000)
            self.topicname_hash_dictionary[topicName] = dk.hex()
            logger.log(logging.WARNING, "Topic names: " + topicName + ", and its first hash value: " + dk.hex() )
            
        self.publish_success_topic_hash.append(topicName)

    

        return client

    def real_topic_hash_publish(self, client: mqtt, topicName, message):
        def on_publish(client, obj, mid):
            logger.log(logging.INFO, "Puback was received, messageID =" + str(mid))
            puback = self.get_puback()
            index1 = puback.index(b'::::')
            mac_real =  puback[index1+4:]
            byte_packet_id = force_bytes(str(mid), 'utf-8')
            message = byte_packet_id 
            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(message)
            signature = h.finalize()
            if mac_real == signature:
                logger.log(logging.INFO, "Signature of PUBACK is verified.")
            else:
                logger.log(logging.ERROR, "Signature of PUBACK is not verified.")


        client.on_publish = on_publish
        logger.log(logging.INFO, "----Function to publish to topic: " + topicName )
        logger.log(logging.INFO, "Message to be published: " + message)

      
        hashed_topic_name = self.topicname_hash_dictionary[topicName]
        topicName_byte = force_bytes(hashed_topic_name)
        choiceTokenhex = self.choiceTokenDictionary[topicName]
        choiceToken = unhexlify(choiceTokenhex)
        logger.log(logging.WARNING, "Hashed topic name: " + hashed_topic_name)
        

        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(topicName_byte)
        signature = h.finalize()
        #signature = b'broken'

        topic_publish = topicName_byte + b'::::' + signature

        backend = default_backend()
        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(topic_publish) + padder.finalize()
        encrypted_topic = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_topic_hex = encrypted_topic.hex()
        #print("Authenticated encryption version of the topic name to be published: ", encrypted_topic_hex)
        logger.log(logging.INFO, "Authenticated encryption version of the topic name to be published: " + encrypted_topic_hex)

        message_byte = force_bytes(message)

        choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
        #print("245 choiceTokenKEY: ", choicetoken_key)



        encryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).padder()
        padded_data = padder.update(message_byte) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_message_byte = force_bytes(encrypted_message)
        #print("Message after encryption with the choice token: ", encrypted_message)
        logger.log(logging.INFO, b'Message after encryption with the choice token: '+ encrypted_message)

        qos = 1
        retainFlag = False
        msgid = self._mid_generate()
        hash_message_str = str(qos) + str(retainFlag) + str(msgid)
        hash_message_bytes = encrypted_message_byte + force_bytes(hash_message_str)


        h = hmac.HMAC(self.session_key, hashes.SHA256())
        h.update(hash_message_bytes)
        signature2 = h.finalize()

        message_publish = encrypted_message_byte + b'::::' + signature2


        encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
        padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
        padded_data = padder.update(message_publish) + padder.finalize()
        encrypted_message2 = encryptor.update(padded_data) + encryptor.finalize()
        #print("Message after authenticated encyption with the session key: ", encrypted_message2)
        logger.log(logging.INFO, b'Message after authenticated encyption with the session key: '+ encrypted_message2)

        client.publish(encrypted_topic_hex, encrypted_message2 , qos = qos, retain = retainFlag, msgid=msgid)

        for topic, topicHash in self.topicname_hash_dictionary.items():
            if topic != topicName:
            
                topicName_byte = force_bytes(topicHash)
                h = hmac.HMAC(self.session_key, hashes.SHA256())

                h.update(topicName_byte)
                signature = h.finalize()
                #signature = b'broken'

                topic_publish = topicName_byte + b'::::' + signature

                logger.log(logging.WARNING, "Real topic name: " + topic)
                logger.log(logging.WARNING, "Hashed topic name: " + topicHash)

                backend = default_backend()
                encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
                padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
                padded_data = padder.update(topic_publish) + padder.finalize()
                encrypted_topic = encryptor.update(padded_data) + encryptor.finalize()
                encrypted_topic_hex = encrypted_topic.hex()
                #print("Authenticated encryption version of the topic name to be published: ", encrypted_topic_hex)
                logger.log(logging.INFO, "Authenticated encryption version of the topic name to be published: " + encrypted_topic_hex)
                random_message = "dnckjdncknvkefnvkncvknvkcvn"

                message_byte = force_bytes(random_message)

                
                logger.log(logging.WARNING, b'Choice Token Key: ' + choicetoken_key)


                encryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).encryptor()
                padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).padder()
                padded_data = padder.update(message_byte) + padder.finalize()
                encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
                encrypted_message_byte = force_bytes(encrypted_message)
                #print("Message after encryption with the choice token: ", encrypted_message)
                logger.log(logging.INFO, b'Message after encryption with the choice token: '+ encrypted_message)

                qos = 1
                retainFlag = False
                msgid = self._mid_generate()
                hash_message_str = str(qos) + str(retainFlag) + str(msgid)
                hash_message_bytes = encrypted_message_byte + force_bytes(hash_message_str)


                h = hmac.HMAC(self.session_key, hashes.SHA256())
                h.update(hash_message_bytes)
                signature2 = h.finalize()

                message_publish = encrypted_message_byte + b'::::' + signature2


                encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
                padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
                padded_data = padder.update(message_publish) + padder.finalize()
                encrypted_message2 = encryptor.update(padded_data) + encryptor.finalize()
                #print("Message after authenticated encyption with the session key: ", encrypted_message2)
                logger.log(logging.INFO, b'Message after authenticated encyption with the session key: '+ encrypted_message2)
                client.publish(encrypted_topic_hex, encrypted_message2 , qos = qos, retain = retainFlag, msgid=msgid)

        salt_poly = self.polynomial_func(self.count,self.polynomials[0],self.polynomials[1],self.polynomials[2],self.polynomials[3])
        salt_poly = str(salt_poly)
        logger.log(logging.WARNING, "salt_poly: " + salt_poly + ", and counter value: " + str(self.count) )
        self.count +=1
        
        for topic, topicHash in self.topicname_hash_dictionary.items():
            logger.log(logging.WARNING, "Topic names: " + topic + ", and its old hash value: " + topicHash )
            dk = hashlib.pbkdf2_hmac('sha512', topicHash.encode(), salt_poly.encode(), 100000)
            self.topicname_hash_dictionary[topic] = dk.hex()
            logger.log(logging.WARNING, "Topic names: " + topic + ", and its new hash value: " + dk.hex() )
        return client
    

    def real_topic_hash_subscribe(self, client: mqtt, topicname):
        def on_message(client, userdata, msg):
           
            logger.log(logging.INFO, "--- 2060 -Publish message was received from broker")
            data = msg.payload
            actual_data = data[2:]
          
            logger.log(logging.INFO, "Encrypted topic: " + msg.topic )
            logger.log(logging.INFO, b'Encrypted payload: ' + actual_data)
            topic_hex = msg.topic
            
        

            topic_byte = unhexlify(topic_hex)
            print(2084)
            backend = default_backend()
            decryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).decryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).unpadder()
            decrypted_data = decryptor.update(topic_byte)
            unpadded = padder.update(decrypted_data) + padder.finalize()
            print(2090)
            index1 = unpadded.index(b'::::')
            topic_name = unpadded[0:index1]
            mac_of_topic_name = unpadded[index1+4:]

            topic_name_str = bytes.decode(topic_name)
            if "topicHashing" in topic_name_str: 
                self.topic_hashing_clear = True
                self.seed_dictionary = {}
                self.count_dictionary = {}
                self.topic_hash_dictionary = {} 
                self.hash_topic_dictionary = {}
                self.topic_subscribe_boolean = {}
                self.subscribe_success = []
                
                
                self.choice_state_dict[topic_name_str] == 0
                topic_name_str = bytes.decode(topic_name)
                choiceTokenhex = self.choiceTokenDictionary[topic_name_str]
                choiceToken = unhexlify(choiceTokenhex)
               
                logger.log(logging.INFO, b'Decrypted topic name: ' + topic_name + b' and its mac: ' + mac_of_topic_name)
                logger.log(logging.INFO, "Choice token of the topic: "+ choiceTokenhex )

                h = hmac.HMAC(self.session_key, hashes.SHA256())
                h.update(topic_name)
                signature = h.finalize()

                if(signature == mac_of_topic_name):
                    #print("The content of the topic name is not changed. Mac of the topic name is correct")
                    logger.log(logging.INFO, "The content of the topic name is not changed. Mac of the topic name is correct")

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
                
                    logger.log(logging.INFO, b'Message after decryption with session key: '+ message_encrypted_with_ct)

                    choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
     

                    decryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).decryptor()
                    padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).unpadder()
                    decrypted_data2 = decryptor.update(message_encrypted_with_ct)
                    unpadded_message = padder.update(decrypted_data2) + padder.finalize()
                    
                    logger.log(logging.INFO, "Topic name: "+  topic_name_str)

                    if msg.retain == 0:
                        retainFlag = False
                    else:
                        retainFlag = True

                    message_hash_str = str(msg.qos) + str(retainFlag) + str(msg.mid)
                    message_bytes_hash = message_encrypted_with_ct + force_bytes(message_hash_str)
                    print("message_hash_str ", message_hash_str)
                    print("message_bytes_hash ", message_bytes_hash)

                    h = hmac.HMAC(self.session_key, hashes.SHA256())
                    h.update(message_bytes_hash)
                    signature = h.finalize()


                    if(signature == mac_of_payload):
                       
                        logger.log(logging.INFO, "The content of the payload is not changed, Mac of the payload is correct")
                        logger.log(logging.INFO, b'Message after decryption with choice token: '+ unpadded_message)
                        index_of_polynomial = unpadded_message.rfind(b'::::')
                        topic_list = unpadded_message[0:index_of_polynomial]
                        polynomial = unpadded_message[index_of_polynomial+4:]
                        polynomial = bytes.decode(polynomial, 'utf-8')
                        logger.log(logging.INFO, "polynomial " + polynomial)
                        poly_list = polynomial.split(",")
                        
                        self.poly_list = poly_list
                        
                        topic_list = topic_list.split(b'::::')
                      
                        for topic_seed_pair in topic_list:

                            index = topic_seed_pair.index(b'$$$$')
                            topicName = topic_seed_pair[0:index]
                            seed = topic_seed_pair[index+4:]
                            topic_name_str = force_str(topicName)
                            seed_str = force_str(seed)
                            self.seed_dictionary[topic_name_str] = seed_str
                            self.count_dictionary[topic_name_str] = 1
                            salt_poly = self.polynomial_func(self.count_dictionary[topic_name_str],int(poly_list[0]),int(poly_list[1]),int(poly_list[2]),int(poly_list[3]))
                            salt_poly = str(salt_poly)
                            logger.log(logging.WARNING, "salt_poly: " + salt_poly + " and its count: " + str(self.count_dictionary[topic_name_str]) + " and it topic name:" + topic_name_str )
                            
                            dk = hashlib.pbkdf2_hmac('sha512', seed_str.encode(), salt_poly.encode(), 100000)
                            dk2 = dk.hex()
                            dk2 = str(dk2)
                            self.topic_hash_dictionary[topic_name_str] = dk2 
                            self.hash_topic_dictionary[dk2] = topic_name_str
                            self.topic_subscribe_boolean[topic_name_str] = False
                            logger.log(logging.WARNING, "Topic names: " + topic_name_str + ", and its first hash value: " + dk2 )
                        
             

                    else:
                        #print("The content of the payload is changed, Mac of the payload is not correct")
                        logger.log(logging.INFO, "The content of the payload is changed, Mac of the payload is not correct")
                        
                else:
                    #print("The content of the topic name is changed")
                    logger.log(logging.INFO, "The content of the topic name is changed")


            else:

                xbool = False
                seed_dictionary = self.seed_dictionary
            
                logger.log(logging.ERROR, seed_dictionary)
                topic_hash_dictionary = self.topic_hash_dictionary
                logger.log(logging.ERROR, topic_hash_dictionary)
                hash_topic_dictionary = self.hash_topic_dictionary
                   
                topic_real = hash_topic_dictionary.get(topic_name_str, "")
                if(topic_real != ""):
                    print(2112)
                    xbool = True
                 
                       
                logger.log(logging.WARNING,"topic_real" + topic_real)
                logger.log(logging.WARNING,"topic_hash" + topic_name_str)
            
                if (xbool == False):
                        logger.log(logging.ERROR,"There is no topic name for this hash")
                        return client
                


                choiceTokenhex = self.choiceTokenDictionary[topic_real]

                choiceToken = unhexlify(choiceTokenhex)

                logger.log(logging.INFO, b'Decrypted topic name: ' + topic_name + b' and its mac: ' + mac_of_topic_name)
                logger.log(logging.INFO, "Choice token of the topic: "+ choiceTokenhex )

                h = hmac.HMAC(self.session_key, hashes.SHA256())
                h.update(topic_name)
                signature = h.finalize()

                if(signature == mac_of_topic_name):
                    #print("The content of the topic name is not changed. Mac of the topic name is correct")
                    logger.log(logging.INFO, "The content of the topic name is not changed. Mac of the topic name is correct")

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
                    #print("Message after decryption with session key: ", message_encrypted_with_ct)
                    logger.log(logging.INFO, b'Message after decryption with session key: '+ message_encrypted_with_ct)

                    choicetoken_key = force_bytes(base64.urlsafe_b64encode(force_bytes(choiceToken))[:32])
                    #print("Choicetoken key: ", choicetoken_key)

                    

                    
                    polynomials = self.poly_list
                    
                    logger.log(logging.WARNING, "counter value: " + str(self.count_dictionary[topic_real])  + " and its topic name:" + topic_real )
                    salt_poly = self.polynomial_func(self.count_dictionary[topic_real],int(polynomials[0]),int(polynomials[1]),int(polynomials[2]),int(polynomials[3]))
                    salt_poly = str(salt_poly)
                    logger.log(logging.WARNING, "salt_poly: " + salt_poly + ", and counter value: " + str(self.count_dictionary[topic_real])  + " and its topic name:" + topic_real )

                   
                    self.seed_dictionary[topic_real] = topic_name_str
                    dk = hashlib.pbkdf2_hmac('sha512', topic_name_str.encode(), salt_poly.encode(), 100000)
                    del self.hash_topic_dictionary[topic_name_str]
                    self.hash_topic_dictionary[dk.hex()] = topic_real
                    self.topic_hash_dictionary[topic_real] = dk.hex()
                    self.count_dictionary[topic_real] +=1
                    logger.log(logging.WARNING, "Real topic name: " + topic_real + ", and its previous hash: " + topic_name_str  + " and its current hash:" + dk.hex())
                    
                   
                    topicName_byte = force_bytes(dk.hex())
                
                
                    msgid = self._mid_generate()
                    print("before msgid sub", msgid)
                    qos = 1

                    topicname_str = dk.hex() + str(qos) + str(msgid)
                    hash_bytes = force_bytes(topicname_str)

                    h = hmac.HMAC(self.session_key, hashes.SHA256())
                    h.update(hash_bytes)
                    signature = h.finalize()
                    #print("MAC of the topic: ", signature )
                    logger.log(logging.INFO, b'MAC of the topic: '+ signature )


                    topicName_subscribe = topicName_byte + b'::::' + signature

                    backend = default_backend()
                    encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
                    padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
                    padded_data = padder.update(topicName_subscribe) + padder.finalize()
                    topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
                    topicNameEncryptedHex = topicNameEncryptedByte.hex()
                    #print("Authenticated encryption version of the topic:" ,topicNameEncryptedHex )
                    logger.log(logging.INFO, "Authenticated encryption version of the topic:" + topicNameEncryptedHex )

                
                    client.subscribe(topicNameEncryptedHex, qos=qos, msgid = msgid)
                    #print("Subscribed to: " ,topicNameEncryptedHex )
                    logger.log(logging.INFO, "Subscribed to: " + topicNameEncryptedHex )
                    send_to_unsub= self.encrypt_mac_one_topic_name(topic_name_str)
                    client.unsubscribe(send_to_unsub)
                    



                    #bir önceki hash versionu için unsubscribe ekle 

                        
                    try:
                        decryptor = Cipher(algorithms.AES(choicetoken_key), modes.ECB(), backend).decryptor()
                        padder = padding2.PKCS7(algorithms.AES(choicetoken_key).block_size).unpadder()
                        decrypted_data2 = decryptor.update(message_encrypted_with_ct)
                        unpadded_message = padder.update(decrypted_data2) + padder.finalize()
                        logger.log(logging.WARNING, "Message is decrypted with choice token ")
                        logger.log(logging.ERROR, b'Message after decryption with choice token: '+ unpadded_message)
                        logger.log(logging.INFO, "Topic name: "+  topic_name_str)
                    except:
                        logger.log(logging.ERROR, "CHOICE TOKEN KEY IS WRONG")
                        return client
             
                        

                    if msg.retain == 0:
                        retainFlag = False
                    else:
                        retainFlag = True

                    message_hash_str = str(msg.qos) + str(retainFlag) + str(msg.mid)
                    message_bytes_hash = message_encrypted_with_ct + force_bytes(message_hash_str)
                    print("message_hash_str ", message_hash_str)
                    print("message_bytes_hash ", message_bytes_hash)

                    h = hmac.HMAC(self.session_key, hashes.SHA256())
                    h.update(message_bytes_hash)
                    signature = h.finalize()


                    if(signature == mac_of_payload):
                        #print("The content of the payload is not changed, Mac of the payload is correct")
                        logger.log(logging.INFO, "The content of the payload is not changed, Mac of the payload is correct")
                        #print("MESSAGE: " ,unpadded_message, "FROM ", topic_namepub )


                    else:
                        #print("The content of the payload is changed, Mac of the payload is not correct")
                        logger.log(logging.INFO, "The content of the payload is changed, Mac of the payload is not correct")

                else:
                    #print("The content of the topic name is changed")
                    logger.log(logging.INFO, "The content of the topic name is changed")


        client.on_message = on_message
        if(self.choice_state_dict[topicname] == 2):
            self.topic_hashing_clear = False
            #print("----Function to subscribe to topic: ", topicname )
            logger.log(logging.INFO, "----Function to subscribe to topic: "+ topicname )
           
            seed = self.seed_dictionary[topicname]
            hash = self.topic_hash_dictionary[topicname]
            logger.log(logging.WARNING,"topic:" + topicname)
            logger.log(logging.WARNING,"seed:" + seed)
            logger.log(logging.WARNING,"hash:" + hash)

            topicName_byte = force_bytes(hash)
            
            
            msgid = self._mid_generate()
            print("before msgid sub", msgid)
            qos = 1

            topicname_str = hash + str(qos) + str(msgid)
            hash_bytes = force_bytes(topicname_str)

            h = hmac.HMAC(self.session_key, hashes.SHA256())
            h.update(hash_bytes)
            signature = h.finalize()
            #print("MAC of the topic: ", signature )
            logger.log(logging.INFO, b'MAC of the topic: '+ signature )


            topicName_subscribe = topicName_byte + b'::::' + signature

            backend = default_backend()
            encryptor = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend).encryptor()
            padder = padding2.PKCS7(algorithms.AES(self.session_key).block_size).padder()
            padded_data = padder.update(topicName_subscribe) + padder.finalize()
            topicNameEncryptedByte = encryptor.update(padded_data) + encryptor.finalize()
            topicNameEncryptedHex = topicNameEncryptedByte.hex()
            #print("Authenticated encryption version of the topic:" ,topicNameEncryptedHex )
            logger.log(logging.INFO, "Authenticated encryption version of the topic:" + topicNameEncryptedHex )

           
            client.subscribe(topicNameEncryptedHex, qos=qos, msgid = msgid)
            #print("Subscribed to: " ,topicNameEncryptedHex )
            logger.log(logging.INFO, "Subscribed to: " + topicNameEncryptedHex )
            self.choice_state_dict[topicname] = 3


            self.subscribe_success.append(topicname)


        return client

    
   

        


    async def run1(self):

        id_client = str(random.randint(0, 100000000))
        self.id_client = id_client
        self.cert_read_fnc()
    
        logger.log(logging.INFO, "CLIENT ID: " + id_client)
        client = self.connect_mqtt(id_client)

        client.loop_start()

        while self.key_establishment_state != 2:
            time.sleep(0.1)
        if self.key_establishment_state == 2:
            await self.subscribe_clientID(client, id_client)
      
        while self.key_establishment_state != 5:
            time.sleep(0.1)
            if self.disconnect_flag == True:
                logger.log(logging.ERROR, "THE RSA SIGNATURE COMMING FROM THE BROKER CANNOT VERIFIED")
                self.disconnect()
                return client

      
        if self.key_establishment_state == 5:
            self.publish_step6(client)
            dh_shared = self.client_diffiehellman.generate_shared_key(self.broker_dh_public_key)

            self.dh_shared_key = dh_shared
       

        logger.log(logging.INFO, b'SHARED DH KEY: ' + self.dh_shared_key)

        sessionkey = force_bytes(base64.urlsafe_b64encode(force_bytes(self.dh_shared_key))[:32])
        self.session_key = sessionkey
       
        logger.log(logging.INFO, b'SESSION KEY DERIVED FROM THE DH SHARED KEY: ' + self.session_key)


        while self.key_establishment_state != 7 and self.session_key == None:
            time.sleep(0.1)
        if self.key_establishment_state == 7:
            await self.subscribe_clientID(client, id_client)  #take the publish message from broker at step 8

        stopWhile = False

        while (self.comming_client_id == None and stopWhile == False):
            time.sleep(0.1)
            if(self._dontreconnect == True):
                logger.log(logging.INFO, "2482")
                self.disconnect_flag = True
                stopWhile = True

        if self.comming_client_id != None:
            incomingClientIdByte = self.comming_client_id
          
            if (bytes.decode(incomingClientIdByte, 'utf-8') == self.id_client ):
                self.key_establishment_state = 8
                logger.log(logging.INFO, "The id received from the broker at step 8 is same as the client ID")
             
            else:
                logger.log(logging.INFO, "The id received from the broker at step 8 is different than the client ID")
                self.disconnect_flag = True
                self.disconnect()

        while self.key_establishment_state != 8:
            time.sleep(0.1)

        if self.key_establishment_state == 8:
            self.publish_step9(client)

        stopWhile = False
        print(2487)

        while self.key_establishment_state != 10:
            time.sleep(0.1)
        if self.key_establishment_state == 10:

            logger.log(logging.INFO, "SELF.KEY_ESTABLSIHMENT_STATE IS 10")

            await self.subscribe_clientID(client, id_client)

            while (self.authenticated == False and stopWhile == False): #bilgesu modification
                time.sleep(0.1)
                print(2505)
                if self.disconnect_flag == True:
                    logger.log(logging.ERROR, "BROKER CANNOT BE AUTHENTICATED DUE TO VERIFICATION FAILURE")
                    self.disconnect()
                    return client

                if(self._dontreconnect == True): #bilgesu modification

                    logger.log(logging.INFO, "BROKER DISCONNECTS YOU BECAUSE IT CANNOT AUTHENTICATE YOU")
                    self.disconnect_flag = True
                    stopWhile = True

            if (self.authenticated == True):
                #print("authenticated true")

                #logger.log(logging.INFO, "SELF.AUTH IS TRUE")


                self.subscribe_encrypted_clientID(client, id_client)
                self.choice_token_state = 1
            #else:
                #logger.log(logging.INFO, "SELF.AUTH IS NOT EQUAL TO TRUE")


            if (self.authenticated == True):
                return client
            else:
                self.disconnect_flag = True
                self.disconnect()
                return -1
            
      

    async def run2(self,client,topicname_list):

        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return client

        self.subscribe_success = [] #initialize list in each subscribe request as 0
       


        print("Topic names received from the gui:", topicname_list)
        #logger.log(logging.INFO, "Topic names received from the gui:"+ topicname_list)

        #modification
        list_failed_suback = []


        for topicname1 in topicname_list:

   

            if ('+' in topicname1 or '#' in topicname1) :
                logger.log(logging.INFO, "1275 :"+ topicname1)
                self.choice_state_dict[topicname1] = 2
                self.subscribe_real_topics(client, topicname1)
                   
            else:
                if (self.disconnect_flag == False):
                    self.choice_state_dict[topicname1] = 0
                    self.publishForChoiceToken(client,topicname1)

              
                while (self.choice_state_dict[topicname1] != 1 and self.disconnect_flag == False):
                        time.sleep(0.1)
                if (self.choice_state_dict[topicname1] == 1 and self.disconnect_flag == False):

                    #if signVErifyFailed received do not send
                    self.subscribe_encrypted_clientID(client, self.id_client)

                #burada fialed to verify maci kontrol et. True ise tekrardan subscribe olma seçeneği gelmeli.
                stop = False
                while (self.choice_state_dict[topicname1] != 2 and self.disconnect_flag == False and stop == False):
                        #stop = True
                        #logger.log(logging.ERROR, " 1295 Bad MAC message received.")
                        time.sleep(0.1)
                if (self.choice_state_dict[topicname1] == 2 and self.disconnect_flag == False):
                    self.subscribe_real_topics(client, topicname1) 

            #modification
            if self.suback_verified == False:
                list_failed_suback.append(topicname1)
                self.suback_verified = True

        #modification
        self.unverified_suback_topics_list = list_failed_suback


        if (self.disconnect_flag == False and self.fail_to_verify_mac == False) :
            self.subscribe4(client, False, False)

        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return client

        self.fail_to_verify_mac = False
        return client
    
    async def run2_2(self,client,topicname_list):

        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return client

        self.subscribe_success = [] #initialize list in each subscribe request as 0

        for topicname1 in topicname_list:


            if ('+' in topicname1 or '#' in topicname1) :
                logger.log(logging.INFO, "1275 :"+ topicname1)
                self.choice_state_dict[topicname1] = 2
                self.subscribe_real_topics(client, topicname1)
                   
            else:
                if (self.disconnect_flag == False):
                    self.choice_state_dict[topicname1] = 0
                    self.publishForChoiceToken(client,topicname1)

                #print("---879 length of topicname1=",len(topicname1))
                #print("---879 self.choice_state_dict[topicname1]=",self.choice_state_dict[topicname1])

                while (self.choice_state_dict[topicname1] != 1 and self.disconnect_flag == False):
                        time.sleep(0.1)
                if (self.choice_state_dict[topicname1] == 1 and self.disconnect_flag == False):

                    #if signVErifyFailed received do not send
                    self.subscribe_encrypted_clientID(client, self.id_client)

                #burada fialed to verify maci kontrol et. True ise tekrardan subscribe olma seçeneği gelmeli.
                stop = False
                while (self.choice_state_dict[topicname1] != 2 and self.disconnect_flag == False and stop == False):
                        #stop = True
                        #logger.log(logging.ERROR, " 1295 Bad MAC message received.")
                        time.sleep(0.1)
                if (self.choice_state_dict[topicname1] == 2 and self.disconnect_flag == False):
                    self.subscribe_real_topics(client, topicname1) 


        if (self.disconnect_flag == False and self.fail_to_verify_mac == False) :
            self.subscribe4(client, False, False)

        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return client

        self.fail_to_verify_mac = False
        return client

    async def run3(self,client,topicname1, message):
            if (self.disconnect_flag == True):
                logger.log(logging.ERROR, "the connection was lost.")
                return self
            self.publish_success = []

            self.fail_to_verify_mac = False
            #print("-------------------run3, topicname: ",topicname1)
            #print("Topic name received from the gui:", topicname1)
            #print("Message received from the gui:", message)
            logger.log(logging.INFO,"Topic name received from the gui:"+ topicname1)
            logger.log(logging.INFO, "Message received from the gui:"+ message)

            if (self.disconnect_flag == False):
                self.choice_state_dict[topicname1] = 0
                self.publishForChoiceToken(client,topicname1)

            while (self.choice_state_dict[topicname1] != 1 and self.disconnect_flag == False):
                    time.sleep(0.1)
            if (self.choice_state_dict[topicname1] == 1 and self.disconnect_flag == False):
                self.subscribe_encrypted_clientID(client, self.id_client)

            stop = False
            while (self.choice_state_dict[topicname1] != 2 and self.disconnect_flag == False and stop == False):
                if(self.fail_to_verify_mac):
                    stop = True
                time.sleep(0.1)

            if (self.choice_state_dict[topicname1] == 2 and self.disconnect_flag == False):
                self.publish_real_topics(client, topicname1, message)

            if (self.disconnect_flag == False and self.fail_to_verify_mac == False) :
                self.subscribe4(client, True, False)

            if (self.disconnect_flag == True):
                logger.log(logging.ERROR, "the connection was lost.")
                return client

            self.fail_to_verify_mac = False
            stop = False
            return client
       

    async def run4(self, client, selected_topics_list):
        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return self

        self.unsub_success = False
        strconcat = ""
        for elem in selected_topics_list:
            strconcat += elem + ", "
            

        strconcat = strconcat[0:len(strconcat)-2]

        #unsubscribe from each topic
        logger.log(logging.INFO,"Topic names to unsubscribe received from the gui:"+ strconcat)


        send_to_unsub_list = await self.encrypt_mac_topic_names(selected_topics_list)


        if self.disconnect_flag == False and len(send_to_unsub_list) > 0:
            client.unsubscribe(send_to_unsub_list)

        if self.disconnect_flag == False:
            bool_false = False
            bool_true = True
            self.subscribe4(client, bool_false, bool_true)

        if self.disconnect_flag == False:

            await self.receive_message_after_unsub(client)

        while(len(self.unverified_unsuback_topics_list)<1):
            time.sleep(0.1)

        if self.received_badmac_unsub == False:
            self.unsub_success = True

        self.received_badmac_unsub = False
        self.fail_to_verify_mac = False

        return client
    
    async def run4_2(self, client, selected_topics_list):
        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return self

        self.unsub_success = False
        strconcat = ""
        for elem in selected_topics_list:
            strconcat += elem + ", "

        strconcat = strconcat[0:len(strconcat)-2]

        #unsubscribe from each topic
        #logger.log(logging.INFO,"Topic names to unsubscribe received from the gui:"+ strconcat)

        send_to_unsub_list = await self.encrypt_mac_topic_names(selected_topics_list)

        if self.disconnect_flag == False and len(send_to_unsub_list) > 0:
            client.unsubscribe(send_to_unsub_list)

        if self.disconnect_flag == False:
            bool_false = False
            bool_true = True
            self.subscribe4(client, bool_false, bool_true)

        if self.disconnect_flag == False:

            await self.receive_message_after_unsub(client)
       

        if self.received_badmac_unsub == False:
            self.unsub_success = True

        self.received_badmac_unsub = False
        self.fail_to_verify_mac = False

        return client
    

    async def connection_for_topic_hashing_publisher(self):   #used by publisher
        
        id_client = str(random.randint(0, 100000000))
        self.id_client = id_client
        self.cert_read_fnc()
        #print("CLIENT ID: " , id_client)
        logger.log(logging.INFO, "CLIENT ID: " + id_client)
        client = self.connect_mqtt(id_client)

        client.loop_start()

        while self.key_establishment_state != 2:
            time.sleep(0.1)
        if self.key_establishment_state == 2:
            await self.subscribe_clientID(client, id_client)
        #print("211", self.key_establishment_state)
        while self.key_establishment_state != 5:
            time.sleep(0.1)

        #print("215", self.key_establishment_state)
        if self.key_establishment_state == 5:
            self.publish_step6(client)
            dh_shared = self.client_diffiehellman.generate_shared_key(self.broker_dh_public_key)

            self.dh_shared_key = dh_shared
        #print("221", self.key_establishment_state)
        #print("SHARED DH KEY: ",self.dh_shared_key)
        logger.log(logging.INFO, b'SHARED DH KEY: ' + self.dh_shared_key)

        sessionkey = force_bytes(base64.urlsafe_b64encode(force_bytes(self.dh_shared_key))[:32])
        self.session_key = sessionkey
        #print("SESSION KEY DERIVED FROM THE DH SHARED KEY: ", self.session_key )
        logger.log(logging.INFO, b'SESSION KEY DERIVED FROM THE DH SHARED KEY: ' + self.session_key)


        while self.key_establishment_state != 7 and self.session_key == None:
            time.sleep(0.1)
        if self.key_establishment_state == 7:
            await self.subscribe_clientID(client, id_client)  #take the publish message from broker at step 8


        while self.comming_client_id == None:
            time.sleep(0.1)
        if self.comming_client_id != None:
            incomingClientIdByte = self.comming_client_id
            #print(type(incomingClientIdByte))
            #print(type(self.id_client))
            if (bytes.decode(incomingClientIdByte, 'utf-8') == self.id_client ):
                self.key_establishment_state = 8
                #print("The id received from the broker at step 8 is same as the client ID")
                logger.log(logging.INFO, "The id received from the broker at step 8 is same as the client ID")
                #print("Message encrypted with ")
                #print(self.key_establishment_state)
            else:
                #print("The id received from the broker at step 8 is different than the client ID")
                logger.log(logging.INFO, "The id received from the broker at step 8 is different than the client ID")
                self.disconnect_flag = True
                self.disconnect()

        while self.key_establishment_state != 8:
            time.sleep(0.1)

        if self.key_establishment_state == 8:
            #print("state 8")
            self.publish_step9(client)

        stopWhile = False #bilgesu modification

        while self.key_establishment_state != 10:
            time.sleep(0.1)
        if self.key_establishment_state == 10:

            #logger.log(logging.INFO, "SELF.KEY_ESTABLSIHMENT_STATE IS 10")

            #print("STATE 10")
            await self.subscribe_clientID(client, id_client)

            while (self.authenticated == False and stopWhile == False): #bilgesu modification
                time.sleep(0.1)

                if(self._dontreconnect == True): #bilgesu modification

                    #logger.log(logging.INFO, "SELF._DONTRECONNECT IS TRUE")
                    logger.log(logging.INFO, "BROKER DISCONNECTS YOU BECAUSE IT CANNOT AUTHENTICATE YOU")
                    

                    self.disconnect_flag = True
                    stopWhile = True

            if (self.authenticated == True):
                #print("authenticated true")

                #logger.log(logging.INFO, "SELF.AUTH IS TRUE")


                self.subscribe_encrypted_clientID(client, id_client)
                self.choice_token_state = 1
            #else:
                #logger.log(logging.INFO, "SELF.AUTH IS NOT EQUAL TO TRUE")

        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return self
        self.publish_topic_hash = [] 

        self.fail_to_verify_mac = False

       
        topicname_hashing = "topicHashing" 
        if (self.disconnect_flag == False):
                self.choice_state_dict[topicname_hashing] = 0
                self.publishForChoiceToken(client,topicname_hashing)
        while (self.choice_state_dict[topicname_hashing] != 1 and self.disconnect_flag == False):
                time.sleep(0.1)
        if (self.choice_state_dict[topicname_hashing] == 1 and self.disconnect_flag == False):
                #if signVErifyFailed received do not send
                self.subscribe_encrypted_clientID(client, self.id_client)
                stop = False
        while (self.choice_state_dict[topicname_hashing] != 2 and self.disconnect_flag == False and stop == False):
                time.sleep(0.1)
        
        
        

        topicname1 = "newParticipant" 

        if (self.disconnect_flag == False):
                self.choice_state_dict[topicname1] = 0
                self.publishForChoiceToken(client,topicname1)

        while (self.choice_state_dict[topicname1] != 1 and self.disconnect_flag == False):
                    time.sleep(0.1)
        if (self.choice_state_dict[topicname1] == 1 and self.disconnect_flag == False):
                self.subscribe_encrypted_clientID(client, self.id_client)

        stop = False
        while (self.choice_state_dict[topicname1] != 2 and self.disconnect_flag == False and stop == False):
                if(self.fail_to_verify_mac):
                    stop = True
                time.sleep(0.1)
                print("1813")
        

        if (self.choice_state_dict[topicname1] == 2 and self.disconnect_flag == False):
                self.subscribe_for_topic_hashing(client, topicname1)
                logger.log(logging.WARNING, "The publisher was subscribed to " + topicname1 + " to learn the   subscribers who want to subscribe itself." )

        if (self.disconnect_flag == False and self.fail_to_verify_mac == False) :
                self.subscribe_for_topic_hashing(client, topicname1)

        if (self.disconnect_flag == True):
                logger.log(logging.ERROR, "the connection was lost.")
                return client

        self.fail_to_verify_mac = False
        stop = False
        return client
    

    async def topic_hashing_publisher_seeds(self, client, topicNameList):   #used by publisher
        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return client
        
        self.publish_success_topic_hash = [] #initialize list in each subscribe request as 0
        
        for topicName in topicNameList:
            if (self.disconnect_flag == False):
                self.choice_state_dict[topicName] = 0
                self.publishForChoiceToken(client,topicName)
            while (self.choice_state_dict[topicName] != 1 and self.disconnect_flag == False):
                time.sleep(0.1)
            if (self.choice_state_dict[topicName] == 1 and self.disconnect_flag == False):
                #if signVErifyFailed received do not send
                self.subscribe_encrypted_clientID(client, self.id_client)
                stop = False
            while (self.choice_state_dict[topicName] != 2 and self.disconnect_flag == False and stop == False):
                time.sleep(0.1)
            self.publisher_hash_session_topics[topicName] = self.choiceTokenDictionary[topicName]
            if (self.disconnect_flag == False and self.fail_to_verify_mac == False) :
                self.subscribe_for_topic_hashing(client, "newParticipant" )


        str_1 = ""
        for elem in topicNameList:
            str_1 += str(elem) + " "
        logger.log(logging.ERROR, str_1)

        self.publish_seeds(client, topicNameList) 
            

        return client

    

    async def topic_hashing_subscriber_step1(self, client):   #used by subscriber
           
        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return client

       
       
       
        topicname1 = "newParticipant"
        topicname2 = "topicHashing" 

        
        if (self.disconnect_flag == False):
            self.choice_state_dict[topicname2] = 0
            self.publishForChoiceToken(client,topicname2)
         

        while (self.choice_state_dict[topicname2] != 1 and self.disconnect_flag == False):
                time.sleep(0.1)
        if (self.choice_state_dict[topicname2] == 1 and self.disconnect_flag == False):
                #if signVErifyFailed received do not send
                self.subscribe_encrypted_clientID(client, self.id_client)
                stop = False
        while (self.choice_state_dict[topicname2] != 2 and self.disconnect_flag == False and stop == False):
                time.sleep(0.1)

        self.subscribe_success_topic_hash  = 0
      
        if (self.disconnect_flag == False and self.choice_state_dict[topicname2] == 2 ):
            self.choice_state_dict[topicname1] = 0
            self.publishForChoiceToken(client,topicname1)

        while (self.choice_state_dict[topicname1] != 1 and self.disconnect_flag == False):
                time.sleep(0.1)
        if (self.choice_state_dict[topicname1] == 1 and self.disconnect_flag == False):
                #if signVErifyFailed received do not send
                self.subscribe_encrypted_clientID(client, self.id_client)
                stop = False
        while (self.choice_state_dict[topicname1] != 2 and self.disconnect_flag == False and stop == False):
                time.sleep(0.1)

        self.subscribe_success_topic_hash = 0
        if (self.choice_state_dict[topicname1] == 2 and self.disconnect_flag == False):
            self.publish_to_topichashing_clientID(client, topicname1)
            
        
        while (self.subscribe_success_topic_hash != 1 and self.disconnect_flag == False and stop == False):
                time.sleep(0.1)

        if (self.subscribe_success_topic_hash  == 1 and self.disconnect_flag == False):
            self.subscribe_to_topicHashing_publisher(client, topicname2)
        
        while (self.subscribe_success_topic_hash!= 2 and self.disconnect_flag == False and stop == False):
                time.sleep(0.1)
                print(2356)

        if (self.subscribe_success_topic_hash  == 2 and self.disconnect_flag == False):
            print(2362)
            self.subscribe_to_topicHashing_publisher(client, topicname2)
            print(2364)
        
        
        if (self.disconnect_flag == False and self.fail_to_verify_mac == False) :
            self.subscribe_to_topicHashing_publisher(client, topicname2)


        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return client

        self.fail_to_verify_mac = False
        return client
   

    async def hash_session_real_publishes(self, client, topicName, message):      #used by publisher
        logger.log(logging.WARNING,"Topic Name from GUI:" + topicName)
        logger.log(logging.WARNING,"Message from GUI:" + message)
        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return client
        elif (self.disconnect_flag == False and self.MAX_COUNT +1 != self.count):
            self.real_topic_hash_publish(client,topicName, message)
        if (self.count == self.MAX_COUNT +1):
            self.publisher_hash_session_topics.clear()
            self.publisher_seed_dictionary.clear()
            self.topicname_hash_dictionary.clear()
            self.hash_session_end = True
            self.polynomials = []
            self.count = 0
            print("here 2573")
        return client
    
    async def hash_session_real_subscribers(self, client, topic_list):   #used by subscriber
        logger.log(logging.WARNING,"Topic List from GUI:")
        logger.log(logging.WARNING, topic_list)
        for topic in topic_list:
            logger.log(logging.WARNING,"topic:" + topic)
            topic_name_index = topic.index(":")
            topicname = topic[topic_name_index+2:]
            topicname = topicname.strip()
            logger.log(logging.WARNING,"topicname:" + topicname)
            if (self.disconnect_flag == False):
                self.choice_state_dict[topicname] = 0
                self.publishForChoiceToken(client,topicname)
            while (self.choice_state_dict[topicname] != 1 and self.disconnect_flag == False):
                    time.sleep(0.1)
                
            if (self.choice_state_dict[topicname] == 1 and self.disconnect_flag == False):
                    #if signVErifyFailed received do not send
                    self.subscribe_encrypted_clientID(client, self.id_client)
                    stop = False
            while (self.choice_state_dict[topicname] != 2 and self.disconnect_flag == False and stop == False):
                    time.sleep(0.1)
            logger.log(logging.WARNING,self.choice_state_dict)
       
        for topic in topic_list:
            logger.log(logging.WARNING,"topic:" + topic)
            topic_name_index = topic.index(":")
            topicname = topic[topic_name_index+2:]
            topicname = topicname.strip()
            logger.log(logging.WARNING,"topicname:" + topicname)
            hash = self.topic_hash_dictionary[topicname]
            seed = self.seed_dictionary[topicname]
            self.topic_subscribe_boolean[topicname] = True
            logger.log(logging.WARNING,"topic:" + topicname)
            logger.log(logging.WARNING,"seed:" + seed)
            logger.log(logging.WARNING,"hash:" + hash)
            logger.log(logging.WARNING,self.choice_state_dict)

            if (self.choice_state_dict[topicname] == 2 and self.disconnect_flag == False):
                self.real_topic_hash_subscribe(client,topicname)
            while (self.choice_state_dict[topicname] != 3 and self.disconnect_flag == False and stop == False):
                    time.sleep(0.1)

            if (self.choice_state_dict[topicname] == 3 and self.disconnect_flag == False):
                self.real_topic_hash_subscribe(client,topicname)
            
            
            if (self.disconnect_flag == False and self.count_dictionary[topicname] == self.MAX_COUNT +1 ) :
                self.subscribe_to_topicHashing_publisher(client, topicname)


    
            
        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            
        
        return client

    async def run_topic_hash_unsubscribe(self, client, selected_topics_list):
        if (self.disconnect_flag == True):
            logger.log(logging.ERROR, "the connection was lost.")
            return self

        self.unsub_success = False
        strconcat = ""
        hash_list = []
        for elem in selected_topics_list:
            strconcat += elem + ", "
            hash_version = self.topic_hash_dictionary[elem]
            logger.log(logging.INFO,"elem:"+ elem)
            logger.log(logging.INFO,"hash_version:"+ hash_version)
            hash_list.append(hash_version)
            del self.topic_hash_dictionary[elem] 
            del self.hash_topic_dictionary[hash_version]
            del self.seed_dictionary[elem]

        strconcat = strconcat[0:len(strconcat)-2]

        #unsubscribe from each topic
        logger.log(logging.INFO,"hash_list:"+ str(hash_list))
        logger.log(logging.INFO,"Topic names to unsubscribe received from the gui:"+ strconcat)

        send_to_unsub_list = await self.encrypt_mac_topic_names(hash_list)

        if self.disconnect_flag == False and len(send_to_unsub_list) > 0:
            client.unsubscribe(send_to_unsub_list)


        if self.disconnect_flag == False:

            await self.receive_message_after_unsub(client)

        while(len(self.unverified_unsuback_topics_list)<1):
            time.sleep(0.1)

        if self.received_badmac_unsub == False:
            self.unsub_success = True

        self.received_badmac_unsub = False
        self.fail_to_verify_mac = False

        return client






def deneme():
    xwindow=Tk()
    xMqttc1 = MyMQTTClass()
    classobj = xMqttc1
    windowobj = xwindow
    var1=StringVar()

    return [classobj, windowobj]

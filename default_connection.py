import src.paho_folder.mqtt.client as mqtt
import time
import datetime
import random
import logging
from os.path import exists, join
import os
import base64
from django.utils.encoding import force_bytes, force_str
import secrets
import asyncio
#from src.paho_folder.mqtt.client import Client
from tkinter import*
from tkinter import  messagebox
from binascii import unhexlify




logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("default_logging")

MQTT_ERR_NO_CONN = 4




class MyMQTTClass(mqtt.Client):

    def __init__(self):
        super().__init__()   # önce super init fonksiyonunu çağırmak gerekir
        #self.disconnect_flag = False
        self.connected_flag =False
        self._client_id = b''
        self.msg = None
        self.id_client = None
        self.disconnect_flag = False

        #fix for now, will be checked later
        self._sock = None
        self._sockpairR = None
        self._sockpairW = None

        self._dontreconnect = False
        #fix for now, will be checkec later

        self.SubscribeTopicsDictionary = {}
        self.PublishTopicsDictionary = {}
        self.subscribe_success:list = [] #list of true and falses

        self.unsub_success: bool = False





    def on_connect_fail(self, mqttc, obj):
        #print("Connection failed")
        logger.log(logging.INFO, "Connection failed")

    def on_message(self, mqttc, obj, msg):
        #print("PUBLISH message received, topic: " + msg.topic+", QOS:"+str(msg.qos)+", Payload:"+str(msg.payload))
        #logger.log(logging.INFO, b'PUBLISH message received, topic: ' + msg.topic +  b' Payload:' + msg.payload)
        print("PUBLISH message received " + msg.topic+" "+str(msg.qos)+" "+str(msg.payload))
        logger.log(logging.INFO, "----Publish message was received from broker")
        logger.log(logging.INFO, b'payload: ' + msg.payload)
        logger.log(logging.INFO, 'topic: ' + msg.topic )

    def on_publish(self, mqttc, obj, mid):
        #print("PUBLISH message sent, message id: " + str(mid))
        logger.log(logging.INFO, "PUBLISH message sent, message id: " + str(mid))

    def on_subscribe(self, mqttc, obj, mid, granted_qos):
        #print("Subscribed, message id: "+str(mid)+ ", QOS: "+str(granted_qos))
        #print("Suback received, message id: "+str(mid))
        logger.log(logging.INFO, "Suback received, message id: "+ str(mid))


    def on_log(self, mqttc, obj, level, string):
        logger.log(logging.INFO,"--------on_log()----"+ string)



    def on_connect(self, mqttc, obj, flags, rc):
        #print("Connection successful (step 2), return code: "+str(rc))
        logger.log(logging.INFO, "Connection successful (step 2), return code: "+str(rc))
        self.connected_flag = True
        self.key_establishment_state = 2
        self.msg = "connected"

    def connect_mqtt(self, id_client) -> mqtt:
        self._client_id = id_client
        self.connect("176.43.5.64", 1883, 6000)
        #print("---Connection message send to broker (step 1)---")
        logger.log(logging.INFO, "---Connect message sent to broker ---")

        return self


    async def run1x(self):
        id_client = str(random.randint(0, 100000000))
        client = self.connect_mqtt(id_client)
        #client.loop_start()
        self.loop_start()
        print("self.is_connected ", self.is_connected())
        if self.connected_flag != True:
            time.sleep(1.1)
            print("self.is_connected ", self.is_connected())

        if self.connected_flag == True:
            print("self.is_connected ", self.is_connected())
            self.subscribe("tvbox/films/+",2)
            self.subscribe("tvbox/+/netflix",2)
            inp = "n"
            self.disconnect_flag = False
            while (inp != "y"):
                time.sleep(11.1)
                inp = input("do you want to disconnect? y/n")
                if inp == "y":
                        self.disconnect_flag = True
            return client

    def writeToFile(self, time_measured):
        file_path = "runs.txt"
        file = open(file_path, "a")

        # Write data to the file

        current_time = time.time()
        file.write(str(current_time)+ "\t" + str(time_measured)+"\n")

        # Close the file
        file.close()



    async def run1(self):
        start_time = time.time()
        id_client = str(random.randint(0, 100000000))
        self.id_client = id_client
        logger.log(logging.INFO, "CLIENT ID: " + id_client)
        client = self.connect_mqtt(id_client)
        client.loop_start()

        time.sleep(0.1)
        if self.connected_flag != True:
            time.sleep(1.1)

        end_time = time.time()
        time_measured = str(round(end_time - start_time,6))
        self.writeToFile(time_measured=time_measured)

        logger.log(logging.CRITICAL, "CONNECT RUN TIME: " + str(round(end_time - start_time,6)))


        return client



        #client.loop_stop()

    async def run2(self,client,topicname_list):

        self.subscribe_success = [] #initialize list in each subscribe request as 0


        print("Topic names received from the gui:", topicname_list)
        #logger.log(logging.INFO, "Topic names received from the gui:"+ topicname_list)
        for topicname1 in topicname_list:
            if (self.disconnect_flag == False):
                self.SubscribeTopicsDictionary[topicname1] = 0
                self.subscribe(topicname1,1)
                #self.subscribe("tvbox/films/#",1)
                #self.subscribe("tvbox/+/netflix",1)
                #self.SubscribeTopicsDictionary["tvbox/films/#"] = 0
                #self.SubscribeTopicsDictionary["tvbox/+/netflix"] = 0

                self.subscribe_success.append(topicname1)

        return client

    async def run3(self,client,topicname1, message):

            logger.log(logging.INFO,"Topic name received from the gui:"+ topicname1)
            logger.log(logging.INFO, "Message received from the gui:"+ message)

            if (self.disconnect_flag == False):
                client.publish(topicname1, message,qos=1)
                #client.publish("tvbox/films", "test msg1 off",qos=1)
                #client.publish("tvbox/films/bluetv", "test msg1 off",qos=1)
                #client.publish("tvbox/series", "test msg1 off",qos=1)
                #client.publish("tvbox/series/disneyplus", "test msg1 off",qos=1)

            return client
        #client.loop_stop()


    async def run4(self, client, selected_topics_list):
        self.unsub_success = False

        topicsx1 = ""
        for elem in selected_topics_list:
            topicsx1 += elem + ", "

        topicsx1 = topicsx1[0:len(topicsx1)-2]

        #unsubscribe from each topic
        logger.log(logging.INFO,"Topic names to unsubscribe received from the gui:"+ topicsx1)

        if self.disconnect_flag == False:
            client.unsubscribe(topicsx1)

        self.unsub_success = True
        return client








#mqttc.loop_stop()

def deneme():
    xwindow=Tk()
    xMqttc1 = MyMQTTClass()
    classobj = xMqttc1
    windowobj = xwindow
    var1=StringVar()

    return [classobj, windowobj]

import datetime
import queue
import logging
import signal
import time
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk, VERTICAL, HORIZONTAL, N, S, E, W


#from tkinter import*
from tkinter import  messagebox
from tkinter.constants import DISABLED, NORMAL

from client_topichash_connection import MyMQTTClass

from client_topichash_logging import *

import asyncio


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("clientwild_logging")

class TopicHashingSubscriberWindow:
    def __init__(self, base, mqttc):
        self.mqttc = mqttc
        self.client = None

        self.btn11 = tk.Button(base, text="Connect",width=10, command = self.client_run1,state=NORMAL)
        self.btn11.place(x=10,y=10)
    
        self.labl_21 = tk.Label(base, text="Select Topics to Subscribe:",font=("bold", 10))
        self.labl_21.place(x=5,y=80)
        
        self.frame3 = tk.Frame(base)
        self.frame3.place(x=10, y=100)

        self.dummy_list3 = []
        self.list_items3 = tk.Variable(value=self.dummy_list3)
        self.listbox3 = tk.Listbox(
            master=self.frame3,
            height=10,
            width =70,
            listvariable=self.list_items3,
            selectmode=tk.MULTIPLE
        )
        self.listbox3.pack(side=tk.LEFT, fill=tk.BOTH)

        self.scrollbar3 = tk.Scrollbar(self.frame3)
        self.scrollbar3.pack(side = tk.LEFT, fill = tk.BOTH)

        self.listbox3.config(yscrollcommand = self.scrollbar3.set)
        self.scrollbar3.config(command = self.listbox3.yview)
        self.btn_d = tk.Button(base, text='Display',width=10, command = self.run_display,state=DISABLED)
        self.btn_d.place(x=455,y=120)
        self.btn21 = tk.Button(base, text='Subscribe',width=10, command = self.client_run2,state=DISABLED)
        self.btn21.place(x=455,y=160)

        
        self.labl_22 = tk.Label(base, text="Subscribed Topics:",width=20,font=("bold", 10))
        self.labl_22.place(x=-15,y=290)

        #bilgesu modification
        self.frame = tk.Frame(base)
        self.frame.place(x=10, y=310)

        self.dummy_list = []
        self.list_items = tk.Variable(value=self.dummy_list)
        self.listbox = tk.Listbox(
            master=self.frame,
            height=10,
            width = 70,
            listvariable=self.list_items,
            selectmode=tk.MULTIPLE
        )
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH)

        self.scrollbar = tk.Scrollbar(self.frame)
        self.scrollbar.pack(side = tk.LEFT, fill = tk.BOTH)

        self.listbox.config(yscrollcommand = self.scrollbar.set)
        self.scrollbar.config(command = self.listbox.yview)
        #bilgesu modification

        self.btn211 = tk.Button(base, text='Unsubscribe',width=10, command = self.client_run4, state=DISABLED)
        self.btn211.place(x=455, y=330)
        
        

        


    def client_run1(self):

        self.btn11['state'] = DISABLED
        client = asyncio.run(self.mqttc.run1())
        print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
        self.client = client
        self.btn21['state'] = NORMAL
        self.btn211['state'] = NORMAL
        self.btn_d['state'] = NORMAL
        client2 = asyncio.run(self.mqttc.topic_hashing_subscriber_step1(client))
       



    def appendToList(self) -> bool:
        for item in self.mqttc.subscribe_success:
            self.listbox.insert("end", item) 
        return True
   
    

    def selected_items_subscribe(self) -> list:
        return_list = []
        for index in self.listbox3.curselection():
            return_list.append(str(self.listbox3.get(index)))
        return return_list
  


    def run_display(self):
        if self.mqttc.topic_hashing_clear == True:
            self.listbox.delete(0,"end")
            self.listbox3.delete(0,"end")
            self.mqttc.topic_hashing_clear = False
     
        message =  ""
        self.listbox3.delete(0,"end")
        for key,item in self.mqttc.topic_hash_dictionary.items():
            message = "Topic Name: " + key
            self.listbox3.insert("end",message) 

            
      
      
    


    def client_run2(self):
        if (self.mqttc.tick_come == True):
            logger.log(logging.ERROR, "Hash Session start already, you have to wait the next session to subscribe")
        received = self.selected_items_subscribe() 


        subscribed_topics = []
        for i in range(self.listbox.size()):
            elem = self.listbox.get(i)
            subscribed_topics.append(str(elem))


        topic_list = []
        for topic in received:
            topic1x = topic[12:]    # remove leading and trailing spaces
            if (len(topic1x) == 0 or len(topic1x) > 65535 ) :
                logger.log(logging.ERROR,"Subcribe topic name length error, topic: " + topic1x)
            elif ('#/' in topic1x) :
                logger.log(logging.ERROR,"Subcribe topic name wildcard error, topic: " + topic1x)
            elif topic1x in subscribed_topics:
                logger.log(logging.ERROR,"You have already subscribed to this topic: " + topic1x)
                
            else:
                wordlist = topic1x.split('/')
                if any('+' in p or '#' in p for p in wordlist if len(p) > 1) :
                    logger.log(logging.ERROR,"Subcribe topic name wildcard error, topic: " + topic1x)

                else:
                    topic_list.append(topic)
                    logger.log(logging.WARNING,"Will subscribe to topic: " + topic1x)
            
        if(len(topic_list)>0):
            rc = asyncio.run(self.mqttc.hash_session_real_subscribers(self.client,topic_list))
        else:
            logger.log(logging.WARNING,"No topic to subscribe, please select at least one topic to subscribe.")

        
        self.listbox.delete(0,"end")
        self.appendToList()

        if self.mqttc.topic_hashing_clear == True:
            self.listbox.delete(0,"end")
            self.listbox3.delete(0,"end")

            


    def client_run4(self):
        #get cursor selection
        selected_topics = self.selected_items()
        #implement unsubscribe here

        print("Will unsubscribe from", selected_topics)

        rc = asyncio.run(self.mqttc.run_topic_hash_unsubscribe(self.client, selected_topics))




        if self.mqttc.unsub_success:
            for elem in selected_topics:
                idx = self.listbox.get(0, tk.END).index(elem)
                self.listbox.delete(idx)

                #logger.log(logging.INFO, "Successfully unsubscribe from topic: "+ str(elem)) #while loop needed to display this at the very end of client_run4


        print(" rc = asyncio.run(mqttc.run3(mqttc,topicname)) , rc :",rc)




    def selected_items(self) -> list:

        return_list = []

        for index in self.listbox.curselection():
            return_list.append(str(self.listbox.get(index)))

        return return_list






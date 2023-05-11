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
        #self.btn12 = tk.Button(base, text="Disconnect",width=10,state=DISABLED)
        #self.btn12.place(x=110,y=10)

        self.labl_31 = tk.Label(base, text= " Client ID of the Publisher that you want to subscribe:",width=45,font=("bold", 10))
        self.labl_31.place(x=-20,y=60)
        self.entry_31 = tk.Entry(base,state=DISABLED)
        self.entry_31.place(x=10,y=80)
        self.btn31 = tk.Button(base, text='Submit',width=10, command = self.client_publisher,state=DISABLED)
        self.btn31.place(x=140,y=80)

        self.labl_42 = tk.Label(base, text="Subscribed Publishers:",width=20,font=("bold", 10))
        self.labl_42.place(x=330,y=20)

        
        self.frame2 = tk.Frame(base)
        self.frame2.place(x=350, y=40)

        self.dummy_list2 = []
        self.list_items2 = tk.Variable(value=self.dummy_list2)
        self.listbox2 = tk.Listbox(
            master=self.frame2,
            height=5,
            listvariable=self.list_items2,
            selectmode=tk.MULTIPLE
        )
    
        self.listbox2.pack(side=tk.LEFT, fill=tk.BOTH)
        
        self.scrollbar2 = tk.Scrollbar(self.frame2)
        self.scrollbar2.pack(side = tk.LEFT, fill = tk.BOTH)

        self.listbox2.config(yscrollcommand = self.scrollbar2.set)
        self.scrollbar2.config(command = self.listbox2.yview)
        

        self.labl_21 = tk.Label(base, text="Select Topics to Subscribe:",font=("bold", 10))
        self.labl_21.place(x=5,y=180)
        
        self.frame3 = tk.Frame(base)
        self.frame3.place(x=10, y=200)

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
        self.btn_d.place(x=455,y=220)
        self.btn21 = tk.Button(base, text='Subscribe',width=10, command = self.client_run2,state=DISABLED)
        self.btn21.place(x=455,y=260)

        
        self.labl_22 = tk.Label(base, text="Subscribed Topics:",width=20,font=("bold", 10))
        self.labl_22.place(x=5,y=390)

        #bilgesu modification
        self.frame = tk.Frame(base)
        self.frame.place(x=10, y=410)

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
        self.btn211.place(x=455, y=430)
        
        

        


    def client_run1(self):

        self.btn11['state'] = DISABLED
        client = asyncio.run(self.mqttc.run1())
        print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
        self.client = client
        self.btn21['state'] = NORMAL
        self.btn31['state'] = NORMAL
        self.entry_31['state'] = NORMAL
        self.btn211['state'] = NORMAL
        self.btn_d['state'] = NORMAL



    def appendToList(self) -> bool:
        for item in self.mqttc.subscribe_success:
            self.listbox.insert("end", item) 
        return True
    
    def appendToList2(self, mqttc:MyMQTTClass) -> bool:
        for item in mqttc.subscribe_success_topic_hash:
            self.listbox2.insert("end", item) 
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
     
        #rc = asyncio.run(self.mqttc.run_display_subscriber(self.client))
        #print(" rc = asyncio.run(mqttc.run2(mqttc,topicname)) , rc :",rc)
        message =  ""
        self.listbox3.delete(0,"end")
        for key,item in self.mqttc.publisher_topic_dictionary.items():
            seed_dictionary = item[0]
            logger.log(logging.ERROR, seed_dictionary)
            hash_dictionary = item[1]
            logger.log(logging.ERROR, hash_dictionary)
            for key2,item2 in seed_dictionary.items():
                message = "Client ID: " + key + ", Topic Name: " + key2
                self.listbox3.insert("end",message) 
      
      
        
   

        
    
    def client_publisher(self):
        publishers = []

        for i in range(self.listbox2.size()):

            elem = self.listbox2.get(i)
            publishers.append(str(elem))

        publisher_id= self.entry_31.get()
        logger.log(logging.INFO, "Topic names received from the gui: "+ publisher_id)
        publisher_id = publisher_id.strip()
        rc = asyncio.run(self.mqttc.topic_hashing_subscriber_step1(self.client,publisher_id))
        print(" rc = asyncio.run(mqttc.run2(mqttc,topicname)) , rc :",rc)


        bool_dummy = self.appendToList2(self.mqttc)

        self.entry_31.delete(0, tk.END) #delete topicname after subscription (the topic anme is alread at the subscribed topics list)

     



    def client_run2(self):
        received = self.selected_items_subscribe() 
        topic_list = []
        for topic in received:
            topic_list.append(topic)
            
        rc = asyncio.run(self.mqttc.hash_session_real_subscribers(self.client,topic_list))
        self.appendToList()
        if self.mqttc.topic_hashing_clear == True:
            self.listbox.delete(0,"end")
            self.listbox3.delete(0,"end")

            


    def client_run4(self):
        #get cursor selection
        selected_topics = self.selected_items()
        #implement unsubscribe here

        print("Will unsubscribe from", selected_topics)

        rc = asyncio.run(self.mqttc.run4(self.client, selected_topics))




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






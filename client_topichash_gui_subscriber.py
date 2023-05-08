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
        self.btn31 = tk.Button(base, text='Submit',width=10, command = self.client_run2,state=DISABLED)
        self.btn31.place(x=140,y=80)


        self.labl_21 = tk.Label(base, text="Subscribe to a Topic:",width=20,font=("bold", 10))
        self.labl_21.place(x=-10,y=160)
        self.entry_21 = tk.Entry(base,state=DISABLED)
        self.entry_21.place(x=10,y=180)
        self.btn21 = tk.Button(base, text='Subscribe',width=10, command = self.client_run2,state=DISABLED)
        self.btn21.place(x=140,y=175)

        self.labl_22 = tk.Label(base, text="Subscribed Topics:",width=20,font=("bold", 10))
        self.labl_22.place(x=260,y=110)

        #bilgesu modification
        self.frame = tk.Frame(base)
        self.frame.place(x=275, y=140)

        self.dummy_list = []
        self.list_items = tk.Variable(value=self.dummy_list)
        self.listbox = tk.Listbox(
            master=self.frame,
            height=10,
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
        self.btn211.place(x=425, y=140)

        


    def client_run1(self):

        self.btn11['state'] = DISABLED
        client = asyncio.run(self.mqttc.run1())
        print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
        self.client = client
        self.btn21['state'] = NORMAL
        self.entry_21['state'] = NORMAL
        self.btn31['state'] = NORMAL
        self.entry_31['state'] = NORMAL



    def appendToList(self, mqttc:MyMQTTClass) -> bool:
        for item in mqttc.subscribe_success:
            self.listbox.insert("end", item) 
        return True

    def client_run2(self):
        subscribed_topics = []

        for i in range(self.listbox.size()):

            elem = self.listbox.get(i)
            subscribed_topics.append(str(elem))

        topicname1= self.entry_21.get()
        logger.log(logging.INFO, "Topic names received from the gui: "+ topicname1)
        list_topicname = topicname1.split(",")

        # check if the topic names in the list are correct
        list_topicname2 = []
        for topic1  in list_topicname :
            topic1x = topic1.strip()    # remove leading and trailing spaces
            if (len(topic1x) == 0 or len(topic1x) > 65535 ) :
                logger.log(logging.ERROR,"Subcribe topic name length error, topic: " + topic1)
            elif ('#/' in topic1x) :
                logger.log(logging.ERROR,"Subcribe topic name wildcard error, topic: " + topic1)
            elif topic1 in subscribed_topics:
                logger.log(logging.ERROR,"You have already subscribed to this topic: " + topic1)
                
            else:
                wordlist = topic1x.split('/')
                if any('+' in p or '#' in p for p in wordlist if len(p) > 1) :
                    logger.log(logging.ERROR,"Subcribe topic name wildcard error, topic: " + topic1)

                else:
                    list_topicname2.append(topic1x)
                    logger.log(logging.WARNING,"Subcribe topic name: " + topic1x)


        rc = asyncio.run(self.mqttc.run2(self.client,list_topicname2))
        print(" rc = asyncio.run(mqttc.run2(mqttc,topicname)) , rc :",rc)


        bool_dummy = self.appendToList(self.mqttc)

        self.entry_21.delete(0, tk.END) #delete topicname after subscription (the topic anme is alread at the subscribed topics list)





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






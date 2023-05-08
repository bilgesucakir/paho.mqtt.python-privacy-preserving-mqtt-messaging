
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

class TopicHashingPublisherWindow:
    def __init__(self, base, mqttc):
        self.mqttc = mqttc
        self.client = None

        self.btn11 = tk.Button(base, text="Connect",width=10, command = self.client_run1,state=NORMAL)
        self.btn11.place(x=10,y=10)
        #self.btn12 = tk.Button(base, text="Disconnect",width=10,state=DISABLED)
        #self.btn12.place(x=110,y=10)


        self.labl_31 = tk.Label(base, text="Publishable Topic:",width=20,font=("bold", 10))
        self.labl_31.place(x=-20,y=60)
        self.entry_31 = tk.Entry(base,state=DISABLED)
        self.entry_31.place(x=10,y=80)
        self.btn31 = tk.Button(base, text='Add',width=10, command = self.appendToPublishabeTopicsList, state=DISABLED)
        self.btn31.place(x=160,y=75)

        self.labl_32 = tk.Label(base, text="Message to Publish:",width=20,font=("bold", 10))
        self.labl_32.place(x=140,y=350)

        self.entry_32 = tk.Text(base, width=28, height=10,state=DISABLED)
        self.entry_32.place(x=160,y=370)
        
        self.labl_22 = tk.Label(base, text="Publishable Topics:",width=20,font=("bold", 10))
        self.labl_22.place(x=-15,y=120)
      

        #bilgesu modification
        self.frame = tk.Frame(base)
        self.frame.place(x=10, y=140)

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

        self.btn33 = tk.Button(base, text='Add Topic to Hash Session',width=20, command = self.appendToHashSessionTopicsList,state=DISABLED)
        self.btn33.place(x=160,y=140)
        

        self.separator = ttk.Separator(base, orient='horizontal')
        self.separator.place(x=-20, y=330, width=30, bordermode="inside")

        self.labl_22 = tk.Label(base, text="Hash Session",font=("bold", 9))
        self.labl_22.place(x=10,y=320)

        self.separator = ttk.Separator(base, orient='horizontal')
        self.separator.place(x=95, y=330, width=455, bordermode="inside")


        self.labl_34 = tk.Label(base, text="Select From List:",width=20,font=("bold", 10))
        self.labl_34.place(x=-20,y=350)

        self.frame2 = tk.Frame(base)
        self.frame2.place(x=10, y=370)

        self.dummy_list2 = []
        self.list_items2 = tk.Variable(value=self.dummy_list2)
        self.listbox2 = tk.Listbox(
            master=self.frame2,
            height=10,
            listvariable=self.list_items2,
            selectmode=tk.SINGLE
        )
        self.listbox2.pack(side=tk.LEFT, fill=tk.BOTH)

        self.scrollbar2 = tk.Scrollbar(self.frame2)
        self.scrollbar2.pack(side = tk.LEFT, fill = tk.BOTH)

        self.listbox2.config(yscrollcommand = self.scrollbar2.set)
        self.scrollbar2.config(command = self.listbox2.yview)


        self.btn32 = tk.Button(base, text='Publish',width=10, command = self.client_run3,state=DISABLED)
        self.btn32.place(x=410,y=370)



    def client_run1(self):

        self.btn11['state'] = DISABLED
        client = asyncio.run(self.mqttc.connection_for_topic_hashing_publisher())
        print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
        self.client = client
        

        self.btn31['state'] = NORMAL
        self.entry_31['state'] = NORMAL


        #self.btn211['state'] = NORMAL



    def appendToList(self, mqttc:MyMQTTClass) -> bool:
        for item in mqttc.publish_success:
            self.listbox.insert("end", item)

    
        return True
    


    def selected_items(self) -> list:

        return_list = []

        for index in self.listbox.curselection():
            return_list.append(str(self.listbox.get(index)))

        return return_list
    

    def appendToPublishabeTopicsList(self):
        received = self.entry_31.get()
        received = received.strip() 

        received_list = received.split(",")
        for item in received_list:
            self.listbox.insert("end", item)

        #check to enable the next button:
        size = self.listbox.size()

        if size > 1:
            self.btn33['state'] = NORMAL


        self.entry_31.delete(0, tk.END) #delete written topicname after the publish



            
    def appendToHashSessionTopicsList(self):
        received = self.selected_items()
        
        for item in received:
            self.listbox2.insert("end", item)

        #check to enable publish mgs enrty and publish button
        size = self.listbox2.size()

        if size > 0:
            self.btn32['state'] = NORMAL
            self.entry_32['state'] = NORMAL


        self.entry_32.delete(1.0, tk.END) #delete written message in textbox after the publish


    def  client_run3(self):
        topicname1 = self.entry_31.get()
        topicname1 = topicname1.strip()    # remove leading and trailing spaces
        print("TOPICNAME1",topicname1)
        message = self.entry_32.get("1.0",tk.END)
        # Search for + or # in a topic.
        if '+' in topicname1 or '#' in topicname1 :
            logger.log(logging.ERROR,"Publish topic name should not include the + or # wildcards")
        elif len(topicname1) > 65535:
            logger.log(logging.ERROR,"Publish topic name should have length less than 65535 ")
        else:
            logger.log(logging.WARNING,"Publish topic name: " + topicname1)
            rc = asyncio.run(self.mqttc.run3(self.client,topicname1, message))
            print(" rc = asyncio.run(mqttc.run3(mqttc,topicname)) , rc :",rc)
        
        bool_dummy = self.appendToList(self.mqttc)

        #logger.log(lvl, self.message.get())

        self.entry_31.delete(0, tk.END) #delete written topicname after the publish
        self.entry_32.delete(1.0, tk.END) #delete written message in textbox after the publish






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
        self.label_id = None
    

        self.btn11 = tk.Button(base, text="Connect",width=10, command = self.client_run1,state=NORMAL)
        self.btn11.place(x=10,y=10)
        #self.btn12 = tk.Button(base, text="Disconnect",width=10,state=DISABLED)
        #self.btn12.place(x=110,y=10)
        self.labl_id1 = tk.Label(base, text = "", width=20,font=("bold", 10))
        self.labl_id1.place(x=125,y=10)
        

      
        self.labl_31 = tk.Label(base, text="Topic Name:",width=20,font=("bold", 10))
        self.labl_31.place(x=-35,y=60)
        self.entry_31 = tk.Entry(base,state=DISABLED)
        self.entry_31.place(x=10,y=80)
        self.btn31 = tk.Button(base, text='Add to Publishable Topics',width=25, command = self.appendToPublishabeTopicsList, state=DISABLED)
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

        self.btn33 = tk.Button(base, text='Add Topic to Hash Session',width=25, command = self.appendToHashSessionTopicsList,state=DISABLED)
        self.btn33.place(x=160,y=140)

        self.btn331 = tk.Button(base, text='Remove from Publishable Topics',width=25, command = self.removeFromPublishableTopics,state=DISABLED)
        self.btn331.place(x=160,y=170)

        self.btn_start = tk.Button(base, text='Start Hash Session',width=25, command = self.start_session,state=DISABLED)
        self.btn_start.place(x=160,y=240)
        


        self.separator = ttk.Separator(base, orient='horizontal')
        self.separator.place(x=-20, y=330, width=25, bordermode="inside")

        self.labl_22 = tk.Label(base, text="Hash Session",font=("bold", 9))
        self.labl_22.place(x=5,y=320)

        self.separator = ttk.Separator(base, orient='horizontal')
        self.separator.place(x=90, y=330, width=460, bordermode="inside")



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

        if(self.mqttc.disconnect_flag == True):
            self.base.quit()

        self.btn11['state'] = DISABLED
        client = asyncio.run(self.mqttc.connection_for_topic_hashing_publisher())
        print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
        self.client = client
        

        self.btn31['state'] = NORMAL
        self.entry_31['state'] = NORMAL
       
        self.label_id = self.mqttc.id_client
        id = "Client ID: " + self.label_id
        self.labl_id1.config(text = id)
       
       


        #self.btn211['state'] = NORMAL


    def start_session(self):

        self.btn11['state'] = DISABLED
        client = asyncio.run(self.mqttc.start_hash_session(self.client))
        print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
        self.btn32['state'] = NORMAL
        self.btn_start['state'] = DISABLED
        self.client = client
        

    def removeFromPublishableTopics(self):

        selected_topics = self.selected_items()

        for elem in selected_topics:
            idx = self.listbox.get(0, tk.END).index(elem)
            self.listbox.delete(idx)

            logger.log(logging.INFO,"Removed from list of publishable topics: " + elem)



        size = self.listbox.size()
        if size < 1:
            self.btn33['state'] = DISABLED
            self.btn331['state'] = DISABLED

        


    def selected_items(self) -> list:

        return_list = []

        for index in self.listbox.curselection():
            return_list.append(str(self.listbox.get(index)))

        return return_list
    
    def selected_items2(self) -> list:
        xstr = None

        for index in self.listbox2.curselection():
            xstr = str(self.listbox2.get(index))
        return xstr
    

    def appendToPublishabeTopicsList(self):
        received = self.entry_31.get()
        received = received.strip() 

        received_list = received.split(",")

        publishable_topics = []
        for i in range(self.listbox.size()):

            elem = self.listbox.get(i)
            publishable_topics.append(str(elem))


        list_topicname2 = []
        for topic1  in received_list:
            topic1x = topic1.strip()    # remove leading and trailing spaces
            if (len(topic1x) == 0 or len(topic1x) > 65535 ) :
                logger.log(logging.ERROR,"Topic name length error, topic: " + topic1)
            elif topic1x == "#":
                logger.log(logging.ERROR,"Cannot publish to # in topic hashing session.")
            elif ('#/' in topic1x) :
                logger.log(logging.ERROR,"Topic name wildcard error, topic: " + topic1)
            elif topic1 in publishable_topics:
                logger.log(logging.ERROR,"You have already added this topic to hash session: " + topic1)    
            else:
                wordlist = topic1x.split('/')
                if any('+' in p or '#' in p for p in wordlist if len(p) > 1) :
                    logger.log(logging.ERROR,"Topic name wildcard error, topic: " + topic1)
                else:
 
                    list_topicname2.append(topic1x)
                    logger.log(logging.INFO,"Added to list of publishable topics: " + topic1)


        str_1 = ""
        count = 0
        for elem in list_topicname2:
            if count > 0:
                str_1 += ", "
            str_1 += str(elem)
            count += 1

 
        for item in list_topicname2:
            self.listbox.insert("end", item)

       
        #check to enable the next button:
        size = self.listbox.size()

        if size > 1:
            self.btn33['state'] = NORMAL
            self.btn331['state'] = NORMAL


        self.entry_31.delete(0, tk.END) #delete written topicname after the publish



            
    def appendToHashSessionTopicsList(self):
        received = ["1","2","3","4","5","6","7","8","9","10", "11", "12", "13", "14", "15"]
        #received = self.selected_items() 
        hash_session_topics = []
        for i in range(self.listbox2.size()):

            elem = self.listbox2.get(i)
            hash_session_topics.append(str(elem))
        self.btn33['state'] = DISABLED
        


        list_topicname2 = []
        for topic1  in received:
            topic1x = topic1.strip()    # remove leading and trailing spaces
            if (len(topic1x) == 0 or len(topic1x) > 65535 ) :
                logger.log(logging.ERROR,"Topic name length error, topic: " + topic1)
            elif ('#/' in topic1x) :
                logger.log(logging.ERROR,"Topic name wildcard error, topic: " + topic1)
            elif topic1x in hash_session_topics:
                logger.log(logging.ERROR,"You have already added this topic to hash session: " + topic1)
            elif topic1x == "#":
                logger.log(logging.ERROR,"Cannot publish to # in topic hashing session.")
            else:
                wordlist = topic1x.split('/')
                if any('+' in p or '#' in p for p in wordlist if len(p) > 1) :
                    logger.log(logging.ERROR,"Topic name wildcard error, topic: " + topic1)

                else:
                    list_topicname2.append(topic1x)

        
        if len(list_topicname2) > 0:

            str_1 = ""
            count = 0
            for elem in list_topicname2:
                if count > 0:
                    str_1 += ", "
                str_1 += str(elem)
                count += 1


            logger.log(logging.WARNING,"Selected Topics for this Hash Session: " + str_1)
            rc = asyncio.run(self.mqttc.topic_hashing_publisher_seeds(self.client, list_topicname2))

            for item in list_topicname2:
                self.listbox2.insert("end", item)
        else:
            if len(received) < 1:
                logger.log(logging.ERROR,"Please select a topic form publishable topics in order to add a topic to hash session.")


        #check to enable publish mgs enrty and publish button
        size = self.listbox2.size()
        if size > 0:
            self.entry_32['state'] = NORMAL
            self.btn_start['state'] = NORMAL


        self.entry_32.delete(1.0, tk.END) #delete written message in textbox after the publish

 

    def client_run3(self):
        
        topicname1 = self.selected_items2()
        print("TOPICNAME1",topicname1)
        message = self.entry_32.get("1.0",tk.END)
        # Search for + or # in a topic.
        if topicname1 == None:
            logger.log(logging.ERROR,"Please select a topic from hash session topics list to publish a message.")
        elif '+' in topicname1 or '#' in topicname1 :
            logger.log(logging.ERROR,"Publish topic name should not include the + or # wildcards.")
        elif len(topicname1) > 65535:
            logger.log(logging.ERROR,"Publish topic name should have length less than 65535.")
        else:
            #logger.log(logging.WARNING,"Publish topic name: " + topicname1)
            rc = asyncio.run(self.mqttc.hash_session_real_publishes(self.client,topicname1, message))
            print(" rc = asyncio.run(mqttc.run3(mqttc,topicname)) , rc :",rc)
        if(self.mqttc.hash_session_end == True):
            logger.log(logging.WARNING,"Hash session was ended")
            self.btn33['state'] = NORMAL
            self.btn32['state'] = DISABLED
            self.listbox2.delete(0,"end")
            self.entry_32.delete(1.0, tk.END)
            print("here")
        
        
        




        self.entry_31.delete(0, tk.END) #delete written topicname after the publish
        self.entry_32.delete(1.0, tk.END) #delete written message in textbox after the publish





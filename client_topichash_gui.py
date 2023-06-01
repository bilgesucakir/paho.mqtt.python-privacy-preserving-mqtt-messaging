
import datetime
import queue
import logging
import signal
import time
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk, VERTICAL, HORIZONTAL, N, S, E, W
from tkinter import  messagebox
from tkinter.constants import DISABLED, NORMAL
from client_topichash_connection import MyMQTTClass
from client_topichash_logging import *
from client_topichash_gui_publisher import TopicHashingPublisherWindow
from client_topichash_gui_subscriber import TopicHashingSubscriberWindow

import asyncio


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("clientwild_logging")


class MyWindowMqtt:
    def __init__(self, base, mqttc):
        self.mqttc = mqttc
        self.client = None
        self.base = base

        self.btn11 = tk.Button(base, text="Connect",width=10, command = self.client_run1,state=NORMAL)
        self.btn11.place(x=10,y=10)
        #self.btn12 = tk.Button(base, text="Disconnect",width=10,state=DISABLED)
        #self.btn12.place(x=110,y=10)


        self.labl_21 = tk.Label(base, text="Subscribe to a Topic:",width=20,font=("bold", 10))
        self.labl_21.place(x=-10,y=60)
        self.entry_21 = tk.Entry(base,state=DISABLED)
        self.entry_21.place(x=10,y=80)
        self.btn21 = tk.Button(base, text='Subscribe',width=10, command = self.client_run2,state=DISABLED)
        self.btn21.place(x=160,y=75)

        self.labl_22 = tk.Label(base, text="Subscribed Topics:",width=20,font=("bold", 10))
        #self.labl_32.place(x=0,y=160)
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

        self.btn211 = tk.Button(base, text='Unsubscribe',width=10, command = self.client_run4, state=DISABLED)
        self.btn211.place(x=160, y=140)

        self.labl_31 = tk.Label(base, text="Publish to a Topic:",width=20,font=("bold", 10))
        #self.labl_31.place(x=0,y=120)
        self.labl_31.place(x=250,y=60)
        self.entry_31 = tk.Entry(base,state=DISABLED)
        #self.entry_31.place(x=10,y=140)
        self.entry_31.place(x=280,y=80)

        self.labl_32 = tk.Label(base, text="Publish Msg:",width=20,font=("bold", 10))
        #self.labl_32.place(x=0,y=160)
        self.labl_32.place(x=235,y=120)
        self.entry_32 = tk.Text(base, width=28, height=10,state=DISABLED)
        #self.entry_32.place(x=10,y=180)
        self.entry_32.place(x=280,y=140)
        self.btn31= tk.Button(base, text='Publish',width=10, command = self.client_run3,state=DISABLED)
        #self.btn31.place(x=160,y=130)
        self.btn31.place(x=428,y=75)


    def client_run1(self):
      
        
        client = asyncio.run(self.mqttc.run1())
        print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
        if(self.mqttc.disconnect_flag == True):
            self.base.quit()
        else:
            self.btn11['state'] = DISABLED
            self.client = client
            self.btn21['state'] = NORMAL
            self.entry_21['state'] = NORMAL

            self.btn31['state'] = NORMAL
            self.entry_31['state'] = NORMAL
            self.entry_32['state'] = NORMAL

            self.btn211['state'] = NORMAL



    def appendToList(self, mqttc:MyMQTTClass, dont_add_list:list) -> bool:
        for item in mqttc.subscribe_success:
            if item not in dont_add_list:
                self.listbox.insert("end", item)
        return True

    def  client_run2(self): 
        
        if(self.mqttc.disconnect_flag == True):
            self.base.quit()
        subscribed_topics = []
        for i in range(self.listbox.size()):

            elem = self.listbox.get(i)
            subscribed_topics.append(str(elem))

        topicname1= self.entry_21.get()
        #topicname1 = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 21, 22, 23, 24, 25"
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

        dummy_list = []
        dummy_list = self.mqttc.unverified_suback_topics_list

        if len(dummy_list)>0:
            str_2 = ""
            for elem in dummy_list:
                str_2 += elem +  " "
            logger.log(logging.WARNING,"FAILED SUBACK TOPICS : " + str_2)

            rc2 = asyncio.run(self.mqttc.run4_2(self.client,dummy_list))




        bool_dummy = self.appendToList(self.mqttc, dummy_list)
        self.entry_21.delete(0, tk.END) #delete topicname after subscription (the topic anme is alread at the subscribed topics list)



    def  client_run3(self):
        if(self.mqttc.disconnect_flag == True):
            self.base.quit()
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

        #logger.log(lvl, self.message.get())

        self.entry_31.delete(0, tk.END) #delete written topicname after the publish
        self.entry_32.delete(1.0, tk.END) #delete written message in textbox after the publish



    def client_run4(self):
        if(self.mqttc.disconnect_flag == True):
            self.base.quit()
        #get cursor selection
        selected_topics = self.selected_items()

        #initializations
        self.mqttc.unsuback_verified = True
        self.mqttc.unverified_unsuback_topics_list = []

        print("Will unsubscribe from", selected_topics)

        rc = asyncio.run(self.mqttc.run4(self.client, selected_topics))

        dummy_list = []
        dummy_list = self.mqttc.unverified_unsuback_topics_list



        if self.mqttc.unsuback_verified == True:

            if self.mqttc.unsub_success:
                for elem in selected_topics:
                    idx = self.listbox.get(0, tk.END).index(elem)
                    self.listbox.delete(idx)
                    #logger.log(logging.INFO, "Successfully unsubscribe from topic: "+ str(elem)) #while loop needed to display this at the very end of client_run4
        else:
            if len(dummy_list) > 1:
                if dummy_list[0] == False:
                    rc2 = asyncio.run(self.mqttc.run2_2(self.client, selected_topics))
                else:
                    logger.log(logging.ERROR, "should not be here")
            else:
                logger.log(logging.ERROR, "should not be here")


    def selected_items(self) -> list:
        return_list = []

        self.listbox.select_set(0, tk.END) #for sleecting all the topics

        for index in self.listbox.curselection():
            return_list.append(str(self.listbox.get(index)))

        return return_list
    
        

    
class xAppMain:

    def __init__(self, root,mqttc):

        self.root = root
        self.mqttc = mqttc
        self.value = None
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        root.title("MQTT CLIENT")
        root.geometry('340x190')

        # Create the panes and frames
        horizontal_pane = ttk.PanedWindow(self.root,orient=HORIZONTAL)
        horizontal_pane.grid(row=0, column=0, sticky="nsew")
        vertical_pane1 = ttk.PanedWindow(horizontal_pane,orient=VERTICAL,height=500,width=550)
        horizontal_pane.add(vertical_pane1)
      

        form_frame = ttk.Labelframe(vertical_pane1,height=300,width=550)
        vertical_pane1.add(form_frame, weight=1)

        self.client = None
       
        """
        self.var = tk.IntVar()
        self.c1 = tk.Radiobutton(root, text="Option 1", variable=self.var, value=1,
                  command=self.print_selection)
        self.c1.place(x=10,y=10)
        self.c2 = tk.Radiobutton(root, text="Option 2", variable=self.var, value=2,
                  command=self.print_selection)
        self.c2.place(x=10,y=30) 
        self.c3 = tk.Radiobutton(root, text="Option 3", variable=self.var, value=3,
                  command=self.print_selection)
        self.c3.place(x=10,y=50) 
        """
        self.clabel = tk.Label(root, text= "Select an option for connecting to the broker:",font=("bold", 10))
        self.clabel.place(x=10,y=10) 
        self.c1 = tk.Button(root, text="Authenticated Client (Publisher and Subscriber)",width=40, command = self.runxApp1,state=NORMAL)
        self.c1.place(x=10,y=40)

        self.c2 = tk.Button(root, text="Authenticated Topic Hashing Publisher",width=40, command = self.runxApp2,state=NORMAL)
        self.c2.place(x=10,y=80)
        self.c3 = tk.Button(root, text="Authenticated Topic Hashing Subscriber",width=40, command = self.runxApp3,state=NORMAL)
        self.c3.place(x=10,y=120)
      
        
        self.root.protocol('WM_DELETE_WINDOW', self.quit)
        self.root.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)

    def runxApp1(self):
        return xApp1(self.root, self.mqttc)
    def runxApp2(self):
        return xApp2(self.root, self.mqttc)
    def runxApp3(self):
        return xApp3(self.root, self.mqttc)



    def quit(self, *args):
        #self.clock.stop()
        self.root.destroy()



class xApp1:

    def __init__(self, root,mqttc):

        self.root = root
        self.mqttc = mqttc
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        root.title("MQTT DEFAULT AUTH CLIENT")
        root.geometry('1265x680')

        # Create the panes and frames
        horizontal_pane = ttk.PanedWindow(self.root,orient=HORIZONTAL)
        horizontal_pane.grid(row=0, column=0, sticky="nsew")
        vertical_pane1 = ttk.PanedWindow(horizontal_pane,orient=VERTICAL,height=500,width=550)
        horizontal_pane.add(vertical_pane1)
        vertical_pane2 = ttk.PanedWindow(horizontal_pane,orient=VERTICAL,height=500,width=200)
        horizontal_pane.add(vertical_pane2)

        form_frame = ttk.Labelframe(vertical_pane1,height=300,width=550)
        vertical_pane1.add(form_frame, weight=1)

        #third_frame = ttk.Labelframe(vertical_pane1, text="Third Frame",height=200,width=500)
        #vertical_pane1.add(third_frame, weight=2)

        console_frame = ttk.Labelframe(vertical_pane2 , text="Console",height=600,width=200, padding=(5,0,0,0))
        vertical_pane2.add(console_frame, weight=1)


        # Initialize all frames
        self.form = MyWindowMqtt(form_frame,mqttc)
        self.console = ConsoleUi(console_frame)
        self.root.protocol('WM_DELETE_WINDOW', self.quit)
        self.root.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)

    def quit(self, *args):
        #self.clock.stop()
        self.root.destroy()

class xApp2:

    def __init__(self, root,mqttc):

        self.root = root
        self.mqttc = mqttc
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        root.title("MQTT TOPIC HASHING PUBLISHER")
        root.geometry('1265x680')

        # Create the panes and frames
        horizontal_pane = ttk.PanedWindow(self.root,orient=HORIZONTAL)
        horizontal_pane.grid(row=0, column=0, sticky="nsew")
        vertical_pane1 = ttk.PanedWindow(horizontal_pane,orient=VERTICAL,height=500,width=550)
        horizontal_pane.add(vertical_pane1)
        vertical_pane2 = ttk.PanedWindow(horizontal_pane,orient=VERTICAL,height=500,width=200)
        horizontal_pane.add(vertical_pane2)

        form_frame = ttk.Labelframe(vertical_pane1, text="Client", height=300,width=550)
        vertical_pane1.add(form_frame, weight=1)


        console_frame = ttk.Labelframe(vertical_pane2 , text="Console",height=600,width=200, padding=(5,0,0,0))
        vertical_pane2.add(console_frame, weight=1)


        # Initialize all frames
        self.form = TopicHashingPublisherWindow(form_frame,mqttc)
        self.console = ConsoleUi(console_frame)
        self.root.protocol('WM_DELETE_WINDOW', self.quit)
        self.root.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)




    def quit(self, *args):
        #self.clock.stop()
        self.root.destroy()


class xApp3:

    def __init__(self, root,mqttc):

        self.root = root
        self.mqttc = mqttc
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        root.title("MQTT TOPIC HASHING SUBSCRIBER")
        root.geometry('1265x680')

        # Create the panes and frames
        horizontal_pane = ttk.PanedWindow(self.root,orient=HORIZONTAL)
        horizontal_pane.grid(row=0, column=0, sticky="nsew")
        vertical_pane1 = ttk.PanedWindow(horizontal_pane,orient=VERTICAL,height=500,width=550)
        horizontal_pane.add(vertical_pane1)
        vertical_pane2 = ttk.PanedWindow(horizontal_pane,orient=VERTICAL,height=500,width=200)
        horizontal_pane.add(vertical_pane2)

        form_frame = ttk.Labelframe(vertical_pane1,text="Client", height=300,width=550)
        vertical_pane1.add(form_frame, weight=1)

        console_frame = ttk.Labelframe(vertical_pane2 , text="Console",height=600,width=200, padding=(5,0,0,0))
        vertical_pane2.add(console_frame, weight=1)


        # Initialize all frames
        self.form = TopicHashingSubscriberWindow(form_frame,mqttc)
        self.console = ConsoleUi(console_frame)
        self.root.protocol('WM_DELETE_WINDOW', self.quit)
        self.root.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)




    def quit(self, *args):
        #self.clock.stop()
        self.root.destroy()


def main():


    myMqttc1 = MyMQTTClass()
    root = tk.Tk()
    xapp = xAppMain(root,myMqttc1)
    xapp.root.mainloop()



if __name__ == '__main__':
    main()

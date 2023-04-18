
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

from client_connection_class_loggin import MyMQTTClass

from client_logging import *

import asyncio


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("client_logging")

class MyWindowMqtt:
    def __init__(self, base, mqttc):
        self.mqttc = mqttc
        self.client = None

        self.btn11 = tk.Button(base, text="Connect",width=10, command = self.client_run1,state=NORMAL)
        self.btn11.place(x=10,y=10)
        self.btn12 = tk.Button(base, text="Disconnect",width=10,state=DISABLED)
        self.btn12.place(x=110,y=10)


        self.labl_21 = tk.Label(base, text="Subscribe Topic:",width=20,font=("bold", 10))
        self.labl_21.place(x=0,y=60)
        self.entry_21 = tk.Entry(base,state=DISABLED)
        self.entry_21.place(x=10,y=80)
        self.btn21 = tk.Button(base, text='Subscribe',width=10, command = self.client_run2,state=DISABLED)
        self.btn21.place(x=160,y=70)


        self.labl_31 = tk.Label(base, text="Publish Topic:",width=20,font=("bold", 10))
        #self.labl_31.place(x=0,y=120)
        self.labl_31.place(x=260,y=60)
        self.entry_31 = tk.Entry(base,state=DISABLED)
        #self.entry_31.place(x=10,y=140)
        self.entry_31.place(x=280,y=80)

        self.labl_32 = tk.Label(base, text="Publish Msg:",width=20,font=("bold", 10))
        #self.labl_32.place(x=0,y=160)
        self.labl_32.place(x=260,y=100)
        self.entry_32 = tk.Text(base, width=30, height=10,state=DISABLED)
        #self.entry_32.place(x=10,y=180)
        self.entry_32.place(x=270,y=120)
        self.btn31= tk.Button(base, text='Publish',width=10, command = self.client_run3,state=DISABLED)
        #self.btn31.place(x=160,y=130)
        self.btn31.place(x=420,y=70)


    def client_run1(self):
        
        self.btn11['state'] = DISABLED
        client = asyncio.run(self.mqttc.run1())
        print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
        self.client = client
        self.btn21['state'] = NORMAL
        self.entry_21['state'] = NORMAL

        self.btn31['state'] = NORMAL
        self.entry_31['state'] = NORMAL
        self.entry_32['state'] = NORMAL
        
    def  client_run2(self):
        topicname1= self.entry_21.get()
        
        logger.log(logging.INFO, "Topic names received from the gui: "+ topicname1)
        list_topicname = topicname1.split(",")

        rc = asyncio.run(self.mqttc.run2(self.client,list_topicname))
        print(" rc = asyncio.run(mqttc.run2(mqttc,topicname)) , rc :",rc)
        

    def  client_run3(self):
        topicname1= self.entry_31.get()
        print("TOPICNAME1",topicname1)
        message = self.entry_32.get("1.0",tk.END)

        rc = asyncio.run(self.mqttc.run3(self.client,topicname1, message))
        print(" rc = asyncio.run(mqttc.run3(mqttc,topicname)) , rc :",rc)
        
        #logger.log(lvl, self.message.get())


class xApp:

    def __init__(self, root,mqttc):

        self.root = root
        root.title('Mqtt Client')
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        root.title("MQTT CLIENT")
        root.geometry('1600x700')

        # Create the panes and frames
        horizontal_pane = ttk.PanedWindow(self.root,orient=HORIZONTAL)
        horizontal_pane.grid(row=0, column=0, sticky="nsew")
        vertical_pane1 = ttk.PanedWindow(horizontal_pane,orient=VERTICAL,height=600,width=550)
        horizontal_pane.add(vertical_pane1)
        vertical_pane2 = ttk.PanedWindow(horizontal_pane,orient=VERTICAL,height=600,width=200)
        horizontal_pane.add(vertical_pane2)

        form_frame = ttk.Labelframe(vertical_pane1, text="xxxxclient",height=300,width=550)
        vertical_pane1.add(form_frame, weight=1)

        #third_frame = ttk.Labelframe(vertical_pane1, text="Third Frame",height=200,width=500)
        #vertical_pane1.add(third_frame, weight=2)

        console_frame = ttk.Labelframe(vertical_pane2 , text="Console",height=600,width=200)
        vertical_pane2 .add(console_frame, weight=1)


        # Initialize all frames
        self.form = MyWindowMqtt(form_frame,mqttc)
        self.console = ConsoleUi(console_frame)
        #self.third = FormUi(third_frame)

        
        #self.clock = Clock()
        #self.clock.start()
        self.root.protocol('WM_DELETE_WINDOW', self.quit)
        self.root.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)




    def quit(self, *args):
        #self.clock.stop()
        self.root.destroy()


def main():


    myMqttc1 = MyMQTTClass()
    root = tk.Tk()
    xapp = xApp(root,myMqttc1)
    xapp.root.mainloop()



if __name__ == '__main__':
    main()

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

from default_connection import MyMQTTClass

from default_logging import *

import asyncio


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("default client_logging")

class MyWindowMqtt:
    def __init__(self, base, mqttc):
        self.mqttc = mqttc
        self.client = None

        self.btn11 = tk.Button(base, text="Connect",width=10, command = self.client_run1,state=NORMAL)
        self.btn11.place(x=10,y=10)
        #self.btn12 = tk.Button(base, text="Disconnect",width=10,state=DISABLED)
        #self.btn12.place(x=110,y=10)


        


    def client_run1(self):

        self.btn11['state'] = DISABLED
        for i in range(0,200):
            client = asyncio.run(self.mqttc.run1())
        print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
        self.client = client
        self.btn21['state'] = NORMAL
        self.entry_21['state'] = NORMAL

        self.btn31['state'] = NORMAL
        self.entry_31['state'] = NORMAL
        self.entry_32['state'] = NORMAL

        self.btn211['state'] = NORMAL

 
class xApp:

    def __init__(self, root,mqttc):

        self.root = root
        root.title('Mqtt Client')
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        root.title("MQTT CLIENT")
        root.geometry('200x200')

        # Create the panes and frames
        horizontal_pane = ttk.PanedWindow(self.root,orient=HORIZONTAL)
        horizontal_pane.grid(row=0, column=0, sticky="nsew")
        vertical_pane1 = ttk.PanedWindow(horizontal_pane,orient=VERTICAL,height=500,width=550)
        horizontal_pane.add(vertical_pane1)
        vertical_pane2 = ttk.PanedWindow(horizontal_pane,orient=VERTICAL,height=500,width=200)
        horizontal_pane.add(vertical_pane2)

        form_frame = ttk.Labelframe(vertical_pane1, text="xxxxclient",height=300,width=550)
        vertical_pane1.add(form_frame, weight=1)

        #third_frame = ttk.Labelframe(vertical_pane1, text="Third Frame",height=200,width=500)
        #vertical_pane1.add(third_frame, weight=2)

        #console_frame = ttk.Labelframe(vertical_pane2 , text="Console",height=600,width=200, padding=(5,0,0,0))
        #vertical_pane2.add(console_frame, weight=1)


        # Initialize all frames
        self.form = MyWindowMqtt(form_frame,mqttc)
        #self.console = ConsoleUi(console_frame)
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

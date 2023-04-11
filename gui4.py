from tkinter import* 
from tkinter import  messagebox
from connection_class2 import MyMQTTClass


import asyncio
import sys
from io import StringIO

#import signal


class MyWindow:
    def __init__(self, base, mqttc):
        self.mqttc = mqttc
        self.client = None
        self.labl_00 = Label(base, text="Connect",width=15,font=("bold", 15))  
        self.labl_00.place(x=150,y=20)  
        self.btn1 = Button(base, text="Connect",width=10, command = self.client_run1).place(x=300,y=20)
        var1=StringVar() 
        l1=Label(base, textvariable=var1) 
        l1.pack() 
      

        self.labl_0 = Label(base, text="Subscribe",width=15,font=("bold", 15))  
        self.labl_0.place(x=40,y=60)  
        
        self.labl_1 = Label(base, text="Topic Name:",width=20,font=("bold", 10))  
        self.labl_1.place(x=10,y=110)  

        self.entry_1 = Entry(base)  
        self.entry_1.place(x=150,y=110)  
        self.btn1 = Button(base, text='Subscribe',width=10, command = self.client_run2).place(x=300,y=105)

          
        self.labl_3 = Label(base, text="Publish",width=15,font=("bold", 15))  
        self.labl_3.place(x=35,y=190)  
        
        self.labl_2 = Label(base, text="Topic Name",width=20,font=("bold", 10))  
        self.labl_2.place(x=10,y=250) 
        self.entry_02 = Entry(base)  
        self.entry_02.place(x=150,y=250) 

        self.labl_4 = Label(base, text="Message",width=20,font=("bold", 10))  
        self.labl_4.place(x=10,y=290) 
         
        self.entry_04 = Entry(base, width=30)  
        #self.entry_04.place(x=150,y=290)  
        #self.entry_04 = Entry(base, width=30)  
        self.entry_04.place(x=150,y=290) 
        self.btn2= Button(base, text='Publish',width=15, command = self.client_run3).place(x=150,y=460)

        self.text_widget = Text(base, height=10, state="disabled").place(x=10, y=500)

        
    def client_run1(self):
        client = asyncio.run(self.mqttc.run1())
        print("rc = asyncio.run(mqttc.run1()) , rc :",client)
        self.client = client


    def  client_run2(self):
        topicname1= self.entry_1.get()
        print("TOPICNAME1",topicname1)

        rc = asyncio.run(mqttc.run2(self.client,topicname1))
        print("rc = asyncio.run(mqttc.run2(mqttc,topicname)) , rc :",rc)

    def  client_run3(self):
        topicname1= self.entry_02.get()
        print("TOPICNAME1",topicname1)
        message = self.entry_04.get()
        #message = self.entry_04.get("1.0",END) #was like this before

        rc = asyncio.run(mqttc.run3(self.client,topicname1, message))
        print(" rc = asyncio.run(mqttc.run3(mqttc,topicname)) , rc :",rc)

  

def showMsg():  
    messagebox.showinfo('Message', 'You clicked the Submit button!')


mqttc = MyMQTTClass()

"""
client = asyncio.run(mqttc.run1())
print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
topicname1="test1111"
rc = asyncio.run(mqttc.run2(client,topicname1))
print(" rc = asyncio.run(mqttc.run2(mqttc,topicname)) , rc :",rc)
"""



window=Tk()

'''
#bilgesu: update begin
def handler(event):
    window.destroy()
    print('caught ^C')

def check():
    window.after(500, check)  #  time in ms.
#bilgesu: update end
'''


mywin=MyWindow(window, mqttc)
window.geometry('600x600')
window.title("MQTT CLIENT")  

'''
#bilgesu: update begin
signal.signal(signal.SIGINT, lambda x,y : print('terminal ^C') or handler(None))

# this let's the terminal ^C get sampled every so often
window.after(500, check)  #  time in ms.

window.bind_all('<Control-c>', handler)
#bilgesu: update end
'''


window.mainloop()


"""
while mqttc.disconnect_flag != True:
        inp = input("do you want to disconnect? y/n")
        if inp == "y":
                mqttc.disconnect_flag = True

        if (mqttc.disconnect_flag == True):

            if(mqttc._dontreconnect == True): #bilgesu modification
                print("Disconnecting from broker since client is not authenticated and key establishment has stopped.")
            else:
                print("Disconnecting from broker")
            returned = mqttc.disconnect()
"""




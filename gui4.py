from tkinter import* 
from tkinter import  messagebox
from client_connection_class import deneme


import asyncio
import sys
from io import StringIO

import signal


class MyWindow:
    def __init__(self, base, mqttc, var1):
        self.mqttc = mqttc
        self.client = None
        self.var1 = var1
        self.labl_00 = Label(base, text="Connect",width=15,font=("bold", 15))  
        self.labl_00.place(x=15,y=20)  
        self.conn = Button(base, text="Connect",width=15, command=lambda: [self.switch(), self.client_run1()])
        self.conn.place(x=400,y=50)

        var1=StringVar() 
        l1=Label(base, textvariable=self.var1) 
        l1.pack() 
      

        self.labl_0 = Label(base, text="Subscribe",width=15,font=("bold", 15))  
        self.labl_0.place(x=20,y=80)  
        
        self.labl_1 = Label(base, text="Topic Name:",width=20,font=("bold", 10))  
        self.labl_1.place(x=10,y=130)  

        self.entry_1 = Entry(base, state='disabled')  
        self.entry_1.place(x=150,y=130)  
        self.btn1 = Button(base, text='Subscribe',width=15, command = self.client_run2, state='disabled')
        self.btn1.place(x=400,y=125)

          
        self.labl_3 = Label(base, text="Publish",width=15,font=("bold", 15))  
        self.labl_3.place(x=10,y=210)  
        
        self.labl_2 = Label(base, text="Topic Name",width=20,font=("bold", 10))  
        self.labl_2.place(x=10,y=270) 
        self.entry_02 = Entry(base, state='disabled')  
        self.entry_02.place(x=150,y=270) 

        self.labl_4 = Label(base, text="Message",width=20,font=("bold", 10))  
        self.labl_4.place(x=10,y=310) 
         
        self.entry_04 = Entry(base, width=30, state='disabled')  
        self.entry_04.place(x=150,y=310)  

        self.btn2= Button(base, text='Publish',width=15, command = self.client_run3, state='disabled')
        self.btn2.place(x=400,y=305)

        #self.text_widget = Text(base, height=10, state="disabled").place(x=10, y=520)


    def switch(self):
        self.btn2["state"] = NORMAL
        self.btn1["state"] = NORMAL
        self.entry_02["state"] = NORMAL
        self.entry_04["state"] = NORMAL
        self.entry_1["state"] = NORMAL

        self.conn["state"] = DISABLED


        
        
    def client_run1(self):
        client = asyncio.run(self.mqttc.run1())
        print("rc = asyncio.run(mqttc.run1()), rc :",client)
        self.client = client
        var1.set(mqttc.msg)


    def  client_run2(self):
        topicname1= self.entry_1.get()
        print("TOPICNAME1",topicname1)

        rc = asyncio.run(mqttc.run2(self.client,topicname1))
        print("rc = asyncio.run(mqttc.run2(mqttc,topicname)), rc :",rc)

    def  client_run3(self):
        topicname1= self.entry_02.get()
        print("TOPICNAME1",topicname1)
        message = self.entry_04.get()
        #message = self.entry_04.get("1.0",END) #was like this before

        rc = asyncio.run(mqttc.run3(self.client,topicname1, message))
        print(" rc = asyncio.run(mqttc.run3(mqttc,topicname)), rc :",rc)


  

def showMsg():  
    messagebox.showinfo('Message', 'You clicked the Submit button!')


mqttc, window, var1 = deneme()

"""
client = asyncio.run(mqttc.run1())
print("---- rc = asyncio.run(mqttc.run1()) , rc :",client)
topicname1="test1111"
rc = asyncio.run(mqttc.run2(client,topicname1))
print(" rc = asyncio.run(mqttc.run2(mqttc,topicname)) , rc :",rc)
"""






#bilgesu: update begin
def handler(event):
    window.destroy()
    print('caught ^C')

def check():
    window.after(500, check)  #  time in ms.
#bilgesu: update end



mywin=MyWindow(window, mqttc, var1)
window.geometry('600x600')
window.title("MQTT CLIENT")  


#bilgesu: update begin
signal.signal(signal.SIGINT, lambda x,y : print('terminal ^C') or handler(None))

# this let's the terminal ^C get sampled every so often
window.after(500, check)  #  time in ms.

window.bind_all('<Control-c>', handler)
#bilgesu: update end



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




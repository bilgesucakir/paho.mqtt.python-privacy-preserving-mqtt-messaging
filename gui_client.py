from tkinter import* 
from tkinter import  messagebox
from client_connection_class import deneme
from tkinter import ttk


import asyncio
import sys
from io import StringIO

import signal


class MyWindow:
    def __init__(self, root, mqttc, var1):
        

        main_frame = Frame(root)
        main_frame.pack(fill=BOTH, expand=1)

        # Create A Canvas
        my_canvas = Canvas(main_frame)
        my_canvas.pack(side=LEFT, fill=BOTH, expand=1)

        # Add A Scrollbar To The Canvas
        my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
        my_scrollbar.pack(side=RIGHT, fill=Y)

        # Configure The Canvas
        my_canvas.configure(yscrollcommand=my_scrollbar.set)
        my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion = my_canvas.bbox("all")))

        # Create ANOTHER Frame INSIDE the Canvas
        second_frame = Frame(my_canvas)

        # Add that New frame To a Window In The Canvas
        my_canvas.create_window((0,0), window=second_frame, anchor="nw")
       
        
        self.mqttc = mqttc
        self.client = None
        self.var1 = var1
        
        self.labl_00 = Label(second_frame, text="Connect",width=15,font=("bold", 15)) 
        self.labl_00.grid(row = 0, column =0) 
        
        self.conn = Button(second_frame, text="Connect",width=15, command=lambda: [self.switch(), self.client_run1()])
        self.conn.grid(row = 1, column =0)
        #self.conn.place(x=400,y=50)
        
        #self.my_label = Label(second_frame, text="It's Friday Yo!").grid(row=3, column=2)
        

        
        var1=StringVar() 
        self.l1=Label(second_frame, textvariable=self.var1) 
        self.l1.grid(row = 1, column =1)
      

        self.labl_0 = Label(second_frame, text="Subscribe",width=15,font=("bold", 15))  
        self.labl_0.grid(row = 0, column =1) 
        
        self.labl_1 = Label(second_frame, text="Topic Name:",width=20,font=("bold", 10))  
        self.labl_1.grid(row = 1, column =1)   

        self.entry_1 = Entry(second_frame, state='disabled')  
        self.entry_1.grid(row = 2, column =1)  

        self.btn1 = Button(second_frame, text='Subscribe',width=15, command = self.client_run2, state='disabled')
        self.btn1.grid(row = 3, column =1, sticky="N")

          
     

        self.labl_5 = Label(second_frame, text="Publish",width=15,font=("bold", 15))  
        self.labl_5.grid(row = 0, column =3) 
        
        
        self.labl_2 = Label(second_frame, text="Topic Name",width=20,font=("bold", 10))  
        self.labl_2.grid(row = 1, column =3) 
        self.entry_02 = Entry(second_frame, state='disabled')  
        self.entry_02.grid(row = 1, column =3)  

        self.labl_4 = Label(second_frame, text="Message",width=20,font=("bold", 10))  
        self.labl_4.grid(row = 2, column =3) 
         
        #self.entry_04 = Entry(second_frame, width=30, state='disabled')  
        #self.entry_04.grid(row = 3, column =3)  

        self.entry_04 = Text(second_frame, width=25, height=8, state='disabled')  
        self.entry_04.grid(row = 3, column =3) 

        self.btn2= Button(second_frame, text='Publish',width=15, command = self.client_run3, state='disabled')
        self.btn2.grid(row = 4, column =3) 
        
        

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
        #print("rc = asyncio.run(mqttc.run1()), rc :",client)
        self.client = client
        var1.set(mqttc.msg)


    def  client_run2(self):
        topicname1= self.entry_1.get()

        list_topicname = topicname1.split(",")


        #print("Topic name list for subscription",list_topicname)

        rc = asyncio.run(mqttc.run2(self.client, list_topicname))
        #print("rc = asyncio.run(mqttc.run2(mqttc,topicname)), rc :",rc)

    def  client_run3(self):
        topicname1= self.entry_02.get()
        #print("TOPICNAME1",topicname1)
        #message = self.entry_04.get()
        message = self.entry_04.get("1.0",END) #was like this before

        rc = asyncio.run(mqttc.run3(self.client,topicname1, message))
        #print(" rc = asyncio.run(mqttc.run3(mqttc,topicname)), rc :",rc)
    


  



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
    try:
        window.destroy()
        print('caught ^C')
    except Exception as e:
        print(e.args)

def check():
    window.after(500, check)  #  time in ms.
#bilgesu: update end


root=MyWindow(window, mqttc, var1)
window.geometry('600x400')
window.title("MQTT CLIENT")
window.mainloop()  



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




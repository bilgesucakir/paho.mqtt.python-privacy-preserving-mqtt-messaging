from tkinter import* 
from tkinter import  messagebox 
root=Tk() 
root.geometry('800x800') 
 
def my_process():  
#....--do something--  
    var="I did it" 
    var1.set(var)  
  
def my_process2():  
#....--do something else--  
    var2="Do process 2"  
    var1.set(var2)  
  
var1=StringVar()  
  
b1=Button(root,text='press', command=my_process) 
b1.pack() 
b2=Button(root,text='press2', command=my_process2) 
b2.pack() 
l1=Label(root, textvariable=var1) 
l1.pack() 
root.mainloop() 
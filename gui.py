from tkinter import *
from tkinter import Toplevel, Button, Tk, Menu

def donothing():
   x = 0

root = Tk()
root.title('Menu Demo')
menubar = Menu(root)
root.config(menu=menubar)
file_menu = Menu(menubar)

menubar.add_command(label="Connect",)
menubar.add_separator()
menubar.add_command(label="Disconnect", command=donothing)
menubar.add_command(label="Publish", command=donothing)
menubar.add_command(label="Subscribe", command=donothing)
menubar.add_command(label="Subscribe Topic List", command=donothing)
menubar.add_command(label="Publish Topic List", command=donothing)
root.mainloop()



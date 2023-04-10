import tkinter as tk
from tkinter import ttk, Tk, Menu, Button, messagebox
  
 
LARGEFONT =("Verdana", 20)
  
class tkinterApp(tk.Tk):
     
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
         
        # creating a container
        container = tk.Frame(self) 
        container.pack( expand = False)  
        container.grid_rowconfigure(0, weight = 1)
        container.grid_columnconfigure(0, weight = 1)
       

        menu = tk.Menu(container)
        menu.add_command(label="StartPage",
                            command=lambda: self.show_frame(StartPage))
        menu.add_command(label="ConnectPage",
                            command=lambda: self.show_frame(ConnectPage))
        menu.add_command(label="PublishPage",
                            command=lambda: self.show_frame(PublishPage))
        menu.add_command(label="SubscribePage",
                            command=lambda: self.show_frame(SubscribePage))
        menu.add_command(label="SubscribedTopicsPage",
                            command=lambda: self.show_frame(SubscribedTopicsPage))
        menu.add_command(label="PublishedTopicsPage",
                            command=lambda: self.show_frame(PublishedTopicsPage))

        tk.Tk.config(self, menu=menu)
  
        # initializing frames to an empty array
        self.frames = {} 
  
        # iterating through a tuple consisting
        # of the different page layouts
        for F in (StartPage, ConnectPage, PublishPage, SubscribePage, PublishedTopicsPage, SubscribedTopicsPage ):
  
            frame = F(container, self)
  
            # initializing frame of that object from
            # startpage, page1, page2 respectively with
            # for loop
            self.frames[F] = frame
  
            frame.grid(row = 0, column = 0, sticky ="nsew")
  
        self.show_frame(StartPage)
  
    # to display the current frame passed as
    # parameter
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
  
# first window frame startpage



  
class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
         


        # label of frame Layout 2
        label = ttk.Label(self, text ="Start Page", font = LARGEFONT)
         
        # putting the grid in its place by using
        # grid
        label.grid(row = 1, column = 4)

class ConnectPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = ttk.Label(self, text ="Connect Page", font = LARGEFONT)
        label.grid(row = 1, column = 4)

        def showMsg():  
            messagebox.showinfo('Message', 'You clicked the Submit button!')
  
        button = tk.Button( text="Submit", font=("Arial", 15), command=showMsg)
        button.pack() 
  


   


class PublishPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
         
       

        # label of frame Layout 2
        label = ttk.Label(self, text ="Publish Page", font = LARGEFONT)
         
        # putting the grid in its place by using
        # grid
        label.grid(row = 1, column = 4)

    

        

class SubscribePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
         
        
          # label of frame Layout 2
        label = ttk.Label(self, text ="Subscribe Page", font = LARGEFONT)
         
        # putting the grid in its place by using
        # grid
        label.grid(row = 1, column = 3)


  

class PublishedTopicsPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        
       
       
           # label of frame Layout 2
        label = ttk.Label(self, text ="Published Topics Page", font = LARGEFONT)
         
        # putting the grid in its place by using
        # grid
        label.grid(row = 1, column = 3)



class SubscribedTopicsPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
         
      
        # label of frame Layout 2
        label = ttk.Label(self, text ="Subscribed Topics Page", font = LARGEFONT)
         
        # putting the grid in its place by using
        # grid
        label.grid(row = 1, column = 6)






# Driver Code
app = tkinterApp()
app.geometry('750x500') 
app.mainloop()
import tkinter as tk

root = tk.Tk()

# create a frame for the listbox and scrollbar
frame = tk.Frame(root)
frame.place(x=50, y=50)

# create a listbox widget
listbox = tk.Listbox(frame)
listbox.pack(side=tk.LEFT, fill=tk.BOTH)

# add some items to the listbox
for i in range(50):
    listbox.insert(tk.END, f"Item {i+1}")

# create a scrollbar widget
scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# attach the scrollbar to the listbox
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)

# create a label widget with padding from sides
label1 = tk.Label(root, text="This is label 1", padx=10, pady=5)
label1.place(x=200, y=50)

# create a label widget with padding from sides
label2 = tk.Label(root, text="This is label 2", padx=10, pady=5)
label2.place(x=200, y=100)

# create a button widget with padding from sides
button1 = tk.Button(root, text="Button 1", padx=10, pady=5)
button1.place(x=200, y=150)

# create a button widget with padding from sides
button2 = tk.Button(root, text="Button 2", padx=10, pady=5)
button2.place(x=200, y=200)

root.mainloop()

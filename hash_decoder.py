from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
import hashlib
import base64

window = Tk()
window.title("Hash Decoder")
window.minsize(width=500,height=750)
window.config(pady=20)

FONT = ("Arial",12,"bold")
image = ImageTk.PhotoImage(Image.open("hash_decoder.png"))

imageLabel = Label(image=image,pady=8)
imageLabel.pack()

intro_label = Label(text="Welcome to Hash Decoder",font=("Arial",18,"bold"),pady=8)
intro_label.pack()

algorithm_label = Label(text="Please choose an algorithm to decode",font=FONT,pady=8)
algorithm_label.pack()

def base64_decrypted(encrypted_data):
    decrypted_data = base64.b64decode(encrypted_data).decode()
    return decrypted_data
def decryption_process():
    result_entry.delete(0,END)
    decryptionState = radio_state_checked()
    result_flag = False
    result_hash = None
    last_hash = None
    user_hash = hash_entry.get()
    file_name = fileName_entry.get()
    if decryptionState == 0:
        try:
            result_hash = base64_decrypted(user_hash)
            hash_entry.delete(0, END)
            fileName_entry.delete(0, END)
            result_entry.delete(0, END)
            messagebox.showinfo(title="Decrypted", message="Process has done!")
            result_entry.insert(0, result_hash)
        except:
            messagebox.showwarning(title="Warning",message="Please enter base64 hash!")

    else:
        try:
            with open(file_name, mode="r") as f:
                lines = f.readlines()

                if (32 <= len(user_hash) <= 128) and type(user_hash) == str:
                    for line_index in lines:
                        passwd = line_index.strip()

                        if decryptionState == 1:
                            last_hash = hashlib.md5(passwd.encode('utf-8')).hexdigest()
                        elif decryptionState == 2:
                            last_hash = hashlib.sha1(passwd.encode('utf-8')).hexdigest()
                        elif decryptionState == 3:
                            last_hash = hashlib.sha256(passwd.encode('utf-8')).hexdigest()
                        elif decryptionState == 4:
                            last_hash = hashlib.sha512(passwd.encode('utf-8')).hexdigest()

                        if last_hash == user_hash:
                            result_hash = passwd
                            result_flag = True
                            hash_entry.delete(0, END)
                            fileName_entry.delete(0, END)
                            result_entry.delete(0, END)
                            break

                    if result_flag == True:
                        messagebox.showinfo(title="Decrypted", message="Process has done!")
                        result_entry.insert(0, result_hash)
                    else:
                        messagebox.showwarning(title="Failed", message="Process has failed!")
                else:
                    messagebox.showwarning(title="Warning", message="Please enter the hash correctly")
        except FileNotFoundError:
            messagebox.showwarning(title="Warning", message="Please enter a file with extension (.txt)")
def radio_state_checked():
    return algorithm_state_check.get()

algorithm_state_check = IntVar()

base64_radio_button = Radiobutton(text="Base64 (no need file)",value=0,variable=algorithm_state_check,font=FONT,pady=8,command=radio_state_checked)
base64_radio_button.pack()

md5_radio_button = Radiobutton(text="MD5",value=1,variable=algorithm_state_check,font=FONT,pady=8,command=radio_state_checked)
md5_radio_button.pack()

sha1_radio_button = Radiobutton(text="Sha1",value=2,variable=algorithm_state_check,font=FONT,pady=8,command=radio_state_checked)
sha1_radio_button.pack()

sha256_radio_button = Radiobutton(text="Sha256",value=3,variable=algorithm_state_check,font=FONT,pady=8,command=radio_state_checked)
sha256_radio_button.pack()

sha512_radio_button = Radiobutton(text="Sha512",value=4,variable=algorithm_state_check,font=FONT,pady=8,command=radio_state_checked)
sha512_radio_button.pack()

textLabel = Label(text="Enter your hash as hexadecimal",font=FONT,pady=8)
textLabel.pack()

hash_entry = Entry(width=50)
hash_entry.pack()

fileName_label = Label(text="Enter file name (password list)", font=FONT,pady=8)
fileName_label.pack()

fileName_entry = Entry(width=50)
fileName_entry.pack()

decryptButton = Button(text="decrypt",width=10,height=2,command=decryption_process)
decryptButton.pack()

result_label = Label(text="Result", font=FONT,pady=8)
result_label.pack()

result_entry = Entry(width=50)
result_entry.pack()

window.mainloop()
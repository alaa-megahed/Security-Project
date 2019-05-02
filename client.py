#!/usr/bin/env python3
"""Script for Tkinter GUI chat client."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
from common import *
from tkinter import *
from LSBSteg import *
from functools import partial
import hashlib, binascii, os


global error_msg_label
global name_entry
global password_entry
global provided_pw
global login_window
global msg_list
global error_string_var
global error_user_var
global my_msg
global top
global entry_field
global authenticated
global username

def receive():
    global login_window
    global msg_list
    global error_string_var
    global error_user_var
    global my_msg
    global shared_key
    """Handles receiving of messages."""
    while True:
        try:
            data = client_socket.recv(BUFSIZ).decode()
            code, user, msg = decode_msg(data, shared_key)
            if code == broadcast_code:
                msg_list.insert(END, msg)
            elif code == listing_users:
                view_users(msg)
            elif code == private:
                if user in chatting_msg_list:
                    add_message_in_chat_window(chatting_msg_list[user], msg)
            elif code == private_close:
                if user in chatting_windows:
                    top_user = chatting_windows[user]
                    top_user.withdraw()
                    del chatting_windows[user]
                    del chatting_msg_list[user]
                    del my_msg_user_list[user]
            elif code == error_username:
                error_user_var.set(msg)
                print(msg)

            # Authentication-related codes
            # if type login2 (salt from server), generate hash password, send login3(username, hashed password)
            elif code == login2_code:
                hashed_pw = hash_password(provided_pw, msg)
                client_socket.send(encode_msg(login3_code, user, hashed_pw, shared_key))
            elif code == new_window:
                if user not in chatting_windows:
                    start_new_chat_window(user)
            # if type error_authentication --> display error msg, clear username, pw entries
            elif code == error_authentication_code:
                # error_msg_label.set(msg)
                error_string_var.set(msg)
            # if type approve_authentication --> destory login window, display chatting window .. welcome bla bla
            elif code == approve_authentication_code:
                global authenticated
                authenticated = True
                login_window.withdraw()
                chatting_window()

            elif code == server_public_code:
                shared_key = get_shared_key(int(msg), client_secret)

        except OSError:  # Possibly client has left the chat.
            break


def hash_password(password, salt):
    """Hash a password for storing."""
    salt = salt.encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

def generate_salt():
    salt = hashlib.sha256(os.urandom(60)).hexdigest()
    return salt
def add_message_in_chat_window(msg_list, msg):
    msg_list.insert(END, msg)

def process_signup():
    # error_msg_label.set("")
    global error_string_var
    error_string_var.set("")
    provided_username = name_entry.get()
    provided_pw = password_entry.get()

    # check username not empty, no spaces
    if len(provided_username) == 0 or " " in provided_username:
        # error_msg_label.set("Invalid username!")
        error_string_var.set("Invalid username!")
        return

    # check length of pw
    if len(provided_pw) < 8:
        # error_msg_label.set("Short password! ")
        error_string_var.set("Short password!")
        return

    # generate_salt
    salt = generate_salt()

    # hash password
    hashed_pw = hash_password(provided_pw, salt)

    # send to server {msg type: signup_request, user: provided_username, msg: hashed_pw}
    client_socket.send(encode_msg(signup_code, provided_username, hashed_pw, shared_key))


def process_login():
    global provided_pw
    # error_msg_label.set("")
    error_string_var.set("")
    provided_username = name_entry.get()
    provided_pw = password_entry.get()

    # send login1 (request_salt) to server
    client_socket.send(encode_msg(login1_code, provided_username, "", shared_key))



def start_window():
    # open socket with server
    global error_msg_label
    global name_entry
    global password_entry
    global login_window
    global error_string_var
    login_window = Tk()  # This creates the login_window, just a blank one.
    login_window.title('Signup/Login')
    instruction = Label(login_window, text='Please Enter Your Credentials :P \n')
    instruction.grid(row=0, column=0, sticky=E)

    error_string_var = StringVar()
    error_msg_label = Label(login_window, textvariable=error_string_var)
    error_msg_label.grid(row=1, column=0, sticky=E)

    name_label = Label(login_window, text='Username: ')
    password_label = Label(login_window, text='Password: ')
    name_label.grid(row=2, column=0, sticky=W)
    password_label.grid(row=3, column=0, sticky=W)

    name_entry = Entry(login_window)
    password_entry = Entry(login_window, show='*')
    name_entry.grid(row=2, column=1)
    password_entry.grid(row=3, column=1)

    signupButton = Button(login_window, text='Signup', command=process_signup)
    signupButton.grid(columnspan=2, sticky=W)
    loginButton = Button(login_window, text='Login', command=process_login)
    loginButton.grid(columnspan=2, sticky=W)

    login_window.protocol("WM_DELETE_WINDOW", on_closing_login)

    # login_window.mainloop()

def view_users(list_users):
    list_users = re.split(r',', list_users)
    top2 = Toplevel()
    top2.title('Users')
    frame = Frame(top2)
    msg_list2 = Listbox(frame, height=15, width=50)
    msg_list2.pack()
    frame.pack()
    msg_list2.insert(END, "List of Online Users: ")
    for username in list_users:
        msg_list2.insert(END, "User: " + username)

def chatting_window():
    global msg_list
    global my_msg
    global waiting
    global username
    global top
    global entry_field
    global error_user_var

    top = Toplevel()
    top.title("Main")

    messages_frame = Frame(top)

    scrollbar = Scrollbar(messages_frame)  # To navigate through past messages.
    # Following will contain the messages.
    msg_list = Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
    scrollbar.pack(side=RIGHT, fill=Y)
    scrollbar.config(command=msg_list.yview)
    msg_list.pack(side=LEFT, fill=BOTH)
    # msg_list.grid(row=0, column=0, padx=5, rowspan=10, columnspan=5)

    send_frame = Frame(top)
    my_msg = StringVar()  # For the messages to be sent.
    my_msg.set("Type your messages here.")
    entry_field = Entry(send_frame, textvariable=my_msg)
    entry_field.bind("<Return>", send)
    entry_field.pack(side=LEFT, padx=7)
    # entry_field.grid(row=11, column=0, padx=5, columnspan=3)
    send_button = Button(send_frame, text="Send", command=send)
    send_button.pack(side=RIGHT)
    # send_button.grid(row=11, column=3, padx=5, columnspan=2)

    start_frame = Frame(top)
    username = StringVar()  # For the messages to be sent.
    username.set("Type username you want to chat with here.")

    user_field = Entry(start_frame, textvariable=username)
    user_field.pack(side=LEFT, padx=7)
    # user_field.bind("<Return>", start_chat_user)
    # user_field.grid(row=12, column=0, padx=5, columnspan=3)
    start_chat_button = Button(start_frame, text="Start Chat", command=start_chat_user)
    start_chat_button.pack(side=RIGHT)
    # send_button.grid(row=12, column=3, padx=5, columnspan=2)

    list_frame = Frame(top)
    list_users_button = Button(list_frame, text="List Users", command=list_users)
    list_users_button.pack()
    # list_users_button.grid(row=13, column=0, columnspan=5)

    error_user_var = StringVar()
    error_user_var.set("")
    error_user_label = Label(list_frame, textvariable=error_user_var)
    # error_user_label.grid(row= 14, column = 0, sticky = E
    error_user_label.pack()

    messages_frame.pack()
    send_frame.pack()
    start_frame.pack()
    list_frame.pack()
    top.protocol("WM_DELETE_WINDOW", on_closing)

    # top.mainloop()
def send_private_chat(user):
    my_msg_of_user = my_msg_user_list[user]
    msg = my_msg_of_user.get()
    client_socket.send(encode_msg(private, user, msg, shared_key))
    my_msg_of_user.set("")
def start_new_chat_window(user):
    top_new_chat_window = Toplevel()
    top_new_chat_window.title(user)
   
    my_msg_new_chat_window = StringVar()  # For the messages to be sent.
    my_msg_new_chat_window.set("Type your messages.")
    
    msg_list_new_chat_window = Listbox(top_new_chat_window, height=15, width=50)
    msg_list_new_chat_window.grid(row=0, column=0, rowspan=10, columnspan=5)

    my_msg_user_list[user] = my_msg_new_chat_window
    chatting_msg_list[user] = msg_list_new_chat_window
    chatting_windows[user] = top_new_chat_window
    
    entry_field = Entry(top_new_chat_window, textvariable=my_msg_new_chat_window)
    # entry_field.bind("<Return>", partial(send_private_chat, user))
    entry_field.grid(row=11, column=0, padx=5, columnspan=3)

    send_button = Button(top_new_chat_window, text="Send", command=partial(send_private_chat, user))
    send_button.grid(row=11, column=3, padx=5, pady=20, columnspan=2)
    top_new_chat_window.protocol("WM_DELETE_WINDOW", partial(on_closing_user, user))

def start_new_chat_window2(user):
    top_new_chat_window = Toplevel()
    top_new_chat_window.title(user)
    # top_new_chat_window.geometry('500x500')
    
    top_messages_frame = Frame(top_new_chat_window)
    scrollbar = Scrollbar(top_messages_frame)

    my_msg_new_chat_window = StringVar()  # For the messages to be sent.
    my_msg_new_chat_window.set("Type your messages.")

    msg_list_new_chat_window = Listbox(top_messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
    scrollbar.pack(side=RIGHT, fill=Y)
    scrollbar.config(command=msg_list_new_chat_window.yview)
    msg_list_new_chat_window.pack(side=LEFT, fill=BOTH)
    # msg_list_new_chat_window.grid(row=0, column=0, rowspan=10, columnspan=5)

    my_msg_user_list[user] = my_msg_new_chat_window
    chatting_msg_list[user] = msg_list_new_chat_window
    chatting_windows[user] = top_new_chat_window

    chat_frame = Frame(top_new_chat_window)

    entry_field = Entry(chat_frame, textvariable=my_msg_new_chat_window)
    # entry_field.bind("<Return>", partial(send_private_chat, user))
    entry_field.pack(side=LEFT, padx=7)
    # entry_field.grid(row=11, column=0, padx=5, columnspan=3)

    send_button = Button(chat_frame, text="Send", command=partial(send_private_chat, user))
    send_button.pack(side=RIGHT)
    # send_button.grid(row=11, column=3, padx=5, pady=20, columnspan=2)
    top_new_chat_window.protocol("WM_DELETE_WINDOW", partial(on_closing_user, user))
    top_messages_frame.pack()
    chat_frame.pack()

def start_chat_user():
    global username
    global error_user_var

    user = username.get()
    error_user_var.set("")

    if user not in chatting_msg_list:
        client_socket.send(encode_msg(new_window, user,"", shared_key))
        #start_new_chat_window(user)
    else:
        print('you are already talking to that person')
    username.set("")


def send(event=None):  # event is passed by binders.
    """Handles sending of messages."""
    global my_msg
    global top
    global entry_field
    # msg = my_msg.get()
    msg = entry_field.get()

    # my_msg.set("")  # Clears input field.

    if msg == "quit" or my_msg.get() == "quit":
        client_socket.send(encode_msg(close,"","", shared_key))
        client_socket.close()
        top.quit()
    else:
        client_socket.send(encode_msg(broadcast_code,"",msg, shared_key))
        entry_field.delete(0, END)

def on_closing(event=None):
    """This function is to be called when the window is closed."""
    global my_msg
    my_msg.set("quit")
    send()


def on_closing_login():
    global login_window
    login_window.destroy()
    client_socket.send(encode_msg(close_auth, "", "", shared_key))
    client_socket.close()
    sys.exit()

def on_closing_user(username):
    if username in my_msg_user_list:
        chatting_windows[username].withdraw()
        del my_msg_user_list[username]
        del chatting_windows[username]
        del chatting_msg_list[username]
        client_socket.send(encode_msg(private_close, username, "", shared_key))

    else:
        print('Not there!!!')

def list_users(event=None):
    client_socket.send(encode_msg(listing_users,"","",shared_key))

HOST = '127.0.0.1'
PORT = 33000

BUFSIZ = 11434080
ADDR = (HOST, PORT)

my_msg_user_list = {}
chatting_msg_list = {}
chatting_windows = {}

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

receive_thread = Thread(target=receive)
receive_thread.start()

client_secret = generate_private_key()
client_public = generate_public_key(client_secret)
shared_key = dummy_key
client_socket.send(encode_msg(public_key_code, "", str(client_public), dummy_key))

authenticated = False

start_window()

# if authenticated:
mainloop()

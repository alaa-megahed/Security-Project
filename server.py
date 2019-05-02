#!/usr/bin/env python3
"""Server for multithreaded (asynchronous) chat application."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from common import *

database = "database.txt"

def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        welcome_msg = "Greetings from the cave! Now type your name and press enter!"
        # client.send(encode_msg(broadcast_code, "", welcome_msg))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()





def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection."""
    # data = client.recv(BUFSIZ).decode()
    # _, _, name = decode_msg(data)
    #welcome = 'Welcome %s! If you ever want to quit, type quit to exit.' % name
    #client.send(encode_msg(welcome))
    # msg = "%s has joined the chat!" % name
    # broadcast(msg)
    # clients[client] = name
    name = ''
    stored_pw = ''
    shared_key = dummy_key

    while True:
        msg = client.recv(BUFSIZ)
        code, user, msg = decode_msg(msg.decode(), shared_key)
        if code == close:
            #client.send(encode_msg(close,"",""))
            client.close()
            del clients_name_sock[name]
            del clients[client]
            broadcast("%s has left the chat." % name)
            break
        elif  code == broadcast_code:
            broadcast(msg, name+": ")
        elif code == listing_users:
            list_names = gen_list()
            client.send(encode_msg(listing_users, "", list_names, shared_key))
        # Authentication-related codes
        elif code == public_key_code:
            client_public = int(msg)
            client.send(encode_msg(server_public_code, "", str(server_public),dummy_key))
            shared_key = get_shared_key(client_public, server_secret)
        elif code == close_auth:
            client.close()
            break
        elif code == new_window:
            if user in clients_name_sock:
                if user == name:
                    client.send(encode_msg(error_username, "", "can not talk to yourself", shared_key))
                else:
                    open_window(name, user)
                    open_window(user,name)
            else:
                client.send(encode_msg(error_username, "", "invalid username", shared_key))
                print('user :', user, 'not there')
        elif code == private:
            send_private(user, msg, name)
        elif code == private_close:
            client_target = clients_name_sock[user]
            client_target.send(encode_msg(private_close, name, "", shared_keys[client_target]))
        # if msg type signup request
        elif code == signup_code:
            db = load_database()
            valid_username = True
            # check username not existent ..
            for username, pw in db.items():
                if username == user:
                    valid_username = False
                    break
            if valid_username:
                # add user to database
                with open(database, "a") as db_file:
                    db_file.write(user + ' ' + msg + '\n')

                # add user to currently active users
                clients[client] = user
                clients_name_sock[user] = client
                shared_keys[client] = shared_key
                name = user
                # send approve_authentication msg
                approval_msg = encode_msg(approve_authentication_code, user, "welcome", shared_key)
                client.send(approval_msg)

                new_msg = "%s has joined the chat!" % user
                broadcast(new_msg)

            else:
                # else send error_authentication msg (invalid username)
                error_msg = encode_msg(error_authentication_code, user, "Invalid username!", shared_key)
                client.send(error_msg)
        # if msg type login1 (request salt)
        elif code == login1_code:
            db = load_database()
            salt = ''
            valid_username = False
            # search database for username
            for username, pw in db.items():
                if username == user:
                    valid_username = True
                    stored_pw = pw.rstrip()
                    salt = stored_pw[:64]
                    break
            if valid_username:
                # send salt
                client.send(encode_msg(login2_code, user, salt, shared_key))
            else:
                # send error_authentication msg (invalid username)
                error_msg = encode_msg(error_authentication_code, user, "Invalid username!", shared_key)
                client.send(error_msg)
        # if msg type login3
        elif code == login3_code:
            if msg == stored_pw:
                clients[client] = user
                clients_name_sock[user] = client
                shared_keys[client] = shared_key
                name = user
                # send approve_authentication msg
                approval_msg = encode_msg(approve_authentication_code, user, "welcome", shared_key)
                client.send(approval_msg)

                new_msg = "%s has joined the chat!" % user
                broadcast(new_msg)
            else:
                # else send error_authentication msg (invalid password)
                error_msg = encode_msg(error_authentication_code, user, "Invalid password!", shared_key)
                client.send(error_msg)


def open_window(userFrom, userTo):
    to_user_socket = clients_name_sock[userTo]
    encoded_msg_to = encode_msg(new_window, userFrom, "", shared_keys[to_user_socket])
    to_user_socket.send(encoded_msg_to)

def send_private(user, msg, prefix=""):
    private_msg = prefix +": "+ msg
    from_user_socket = clients_name_sock[prefix]
    to_user_socket = clients_name_sock[user]

    encoded_msg_to = encode_msg(private, prefix, private_msg, shared_keys[to_user_socket])
    encoded_msg_from = encode_msg(private, user, private_msg, shared_keys[from_user_socket])



    from_user_socket.send(encoded_msg_from)
    to_user_socket.send(encoded_msg_to)

def gen_list():
    clients_list = clients.values()
    clients_list_str = ""
    for client_name in clients_list:
        if(len(clients_list_str) > 0):
            clients_list_str = clients_list_str + "," + client_name
        else:
            clients_list_str = client_name
    return clients_list_str

def broadcast(msg, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    broadcast_msg = prefix + msg

    for sock in clients:
        encoded_msg = encode_msg(broadcast_code, "", broadcast_msg, shared_keys[sock])
        sock.send(encoded_msg)



def load_database():
    db = {}
    with open(database) as db_file:
        for line in db_file:
            l = line.split(' ')
            db[l[0]] = l[1]
    return db


clients = {}
clients_name_sock = {}
addresses = {}
shared_keys = {}
server_secret = generate_private_key()
server_public = generate_public_key(server_secret)


HOST = ''
PORT = 33000
BUFSIZ = 11434080
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(5)
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()

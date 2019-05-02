# Mesh Tes2al

Mesh Tes2al is a chatting application that utilizes Steganography by hiding the content of messages in images ensuring the confidentiality between both initiator and recipient. The application is composed of a lobby chat room where all users can send and receive broadcast messages. In addition, a user may choose any other online user and start a private chat with them. The application is secured using different security elements including Authentication, Hashing, Encryption (AES), Key Exchange (Diffie–Hellman), and Access control through private chat channels.

## Installation

Mesh Tes2al requires [Python](https://www.python.org/downloads/) v3+ to run. Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the following:

```bash
pip install numpy
pip install hashlib
pip install pycrypto
```


## Running the App
1. Run the server through the Python file __`chat_serv.py`__:
    ```sh
    $ python chat_serv.py
    ```
2. Run the client through the Python file __`chat_clnt.py`__:
    ```sh
    $ python chat_clnt.py
    ```

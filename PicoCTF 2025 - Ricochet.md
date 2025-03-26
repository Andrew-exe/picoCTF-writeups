![alt text](https://github.com/Andrew-exe/picoCTF-writeups/blob/main/Pasted%20image%2020250325232954.png)

From the provided code, we can see that it is a radio-controlled robot challenge with encryption and communication protocol. 

The goal is to exploit the encryption and communication protocol to navigate the robot to a flag. Here are the observations: 
1. The challenge involves controlling a robot through a secure radio communication system 
2. There's a complex encryption mechanism using Diffie-Hellman key exchange and HMAC validation. 
3. The robot controller is currently in a "demo loop" sending predetermined movements: east, south, west, north. 
4. we can use the method receive_radio_messages in readio_interface.py 
5. The nonce used to encrypt the message bounced up by 1 in process_secure_data_request and process_secure_data functions in robotcontroller.py, send_secure_data and recv_secure_data in robot.py. Hence, going each direction will increase nonce by 2. 
6. In robotcontroller.py, there is a message type called: set_addr. Utilizing this message type for the Man-in-the-Middle(MITM) attack. We will use Man-in-the-Middle(MITM) attack. a MITM attach involves intercepting, potentially modifying and retransmitting communication between the robot controller and the robot without either party detecting the interference. 
We can see that it uses two shared keys: shared_hmac_key and dh_key_shared. 
For each picoctf account, the shared_hmac_key is the same. The dh_key_shared is different for each instance. Since it use the shared_hmac_key, we can use the same encrypted message with hmac. 

To go to the flag, the route for the robot to go is: 
east(nonce 1), 
south(nonce 3), 
east(nonce 5), 
north(nonce 7), 
west(nonce 9), 
south(nonce 11), 
east(nonce 13), 
north(nonce 15), 
east(nonce 17) 
south(nonce 19)

In the current demo loop, we already have the hmac for: 
east(nonce 1) 
south(nonce 3) 
north(nonce 7) 
south(nonce 11) 
north(nonce 15) 
east(nonce 17)
south(nonce 19) 

The only hmac we want to get is: 
east(nonce 5) 
west(nonce 9)
east(nonce 13)

By using the MITM attack, when the next move is east, we could advance just the nonce to the desired number and then send it to the controller to get the desired hmac. 

After we get all the hmac for these steps, we can control the robot to go to the flag. 
Below is the code we use. 
```
import requests

import os

import time

import monocypher

import crypto

import json

import sys

import argparse

  

ap = argparse.ArgumentParser()

ap.add_argument("port", nargs='?', default=None)

args = ap.parse_args()

# TODO: you will need to fill this in with the URL of the challenge

if args.port is None:

    portNum = input("Please enter the correct portNum: ")

else:

    portNum = args.port

print(portNum, args.port)

SERVER_URL = f"http://activist-birds.picoctf.net:{portNum}/"

if "captured_messages2.log" in os.listdir('.'):

    os.remove("captured_messages2.log")

  

# Sniff incoming messages

def receive_radio_messages():

    messages = requests.get(SERVER_URL + "/radio_rx").json()

    for log in range(0, len(messages)):

        print("🔍 Sniffed Message:", messages[log])  # Log messages

        # if msg["msg_type"] == "secure_data_response":

        with open("captured_messages2.log", "a") as f:

            f.write(f"{log}: {messages[log]}\n")  # Save encrypted messages

  

    return messages

  

    # messages = requests.get(SERVER_URL + "/radio_rx").json()

    # for msg in messages:

    #     print("🔍 Sniffed Message:", msg)

    # return messages

  

# Inject messages into the radio network

def inject_radio_message(message):

    #print("🚀 Injecting Message:", message)

    requests.post(SERVER_URL + "/radio_tx", json=message)

  

# Start and stop the robot

def start_robot():

    requests.get(SERVER_URL + "/start")

  

def stop_robot():

    requests.get(SERVER_URL + "/stop")

  

# Get board state

def get_board_state():

    return requests.get(SERVER_URL + "/state").json()

  

def get_keys():  # not working

    keys_content = requests.get(SERVER_URL + "/keys.py").text  

    print(keys_content)

  

#get_keys()

  

def craft_message(msg_type, src, dst, payload):

    output = {'msg_type': msg_type, 'src': src, 'dst': dst} | (payload)

    return output

  

class Target():

    def __init__(self, slf_addr, mitm_addr):

        self.slf_addr = slf_addr

        self.mitm_addr = mitm_addr

        self.hmac = os.urandom(32)

        self.dh_key_priv = os.urandom(32)

  

        # Initialize to a random key so we don't accidentally send unencrypted data

        self.dh_key_shared = os.urandom(32)

  

    def set_hmac(self, new_hmac):

        self.hmac = new_hmac

  

    def set_shared_key(self, new_shared_key):

        self.dh_key_shared = new_shared_key

  

    def reset(self):

        self.nonce = 0

        self.movement_counter = 0

  

    def send_message(self, msg):

        inject_radio_message(msg)

  

    def hmac_and_encrypt(self, msg, nonce):

        msg_with_hmac = json.dumps(crypto.add_hmac(msg, nonce, self.hmac))

        msg_encrypted = crypto.encrypt(msg_with_hmac, self.dh_key_shared)

        return msg_encrypted

  

    def decrypt_and_check_hmac(self, msg, nonce):

        msg = crypto.decrypt(msg, self.dh_key_shared)

        if msg is None: return None

        msg_with_hmac = json.loads(msg)

        return crypto.validate_hmac(msg_with_hmac, nonce, self.hmac)

  

class Server(Target):

    def __init__(self, robot):

        super().__init__(32, 16)

        self.robot = robot

        self.nonce = 0

        self.hmacs = {}

  

    def validate_robot(self, challenge):

        self.send_message({

            "msg_type": "validate",

            "src": self.robot.mitm_addr,

            "dst": self.robot.slf_addr,

            'challenge': challenge

        })

  

    def ack_validate_robot(self, response):

        robot.send_message({

            "msg_type": "ack_validate",

            "src": self.mitm_addr,

            "dst": self.slf_addr,

            'response': response

        })

  

    def key_exchange(self, key):

        print("Preforming Key Exchange:")

        self.send_message({

                    "msg_type": "ack_key_exchange",

                    "src": self.mitm_addr,

                    "dst": self.slf_addr,

                    "key": monocypher.compute_key_exchange_public_key(self.dh_key_priv).hex()

                })

        self.dh_key_shared = monocypher.key_exchange(self.dh_key_priv, bytes.fromhex(key))

  

        self.send_message({

                    "msg_type": "key_exchange",

                    "src": self.mitm_addr,

                    "dst": robot.slf_addr,

                    "key": monocypher.compute_key_exchange_public_key(robot.dh_key_priv).hex()

                })

  

    def process_secure_data(self, msg, overwrite=None):

        cmd = json.loads(crypto.decrypt(msg, self.dh_key_shared).decode())

        if not 'secure_data' in self.hmacs.keys():

            self.hmacs['secure_data'] = []

        self.hmacs['secure_data'].append(cmd)

  

        if overwrite:

            cmd = overwrite

        robot.send_secure_msg('secure_data', cmd)

  

    def process_secure_data_request(self, msg, overwrite=None):

        if overwrite:

            cmd = overwrite

        else:

            cmd = json.loads(crypto.decrypt(msg, self.dh_key_shared).decode())

            if not 'secure_data_blank' in self.hmacs.keys():

                self.hmacs['secure_data_blank'] = {}

            self.hmacs['secure_data_blank'][f"{cmd['nonce']}"] = cmd['hmac']

  

        robot.send_secure_msg('secure_data_request', cmd)

  

    def process_secure_data_ack(self, msg, overwrite=None):

        cmd = json.loads(crypto.decrypt(msg, robot.dh_key_shared).decode())

        if not 'secure_data_blank' in self.hmacs.keys():

            self.hmacs['secure_data_blank'] = {}

        self.hmacs['secure_data_blank'][f"{cmd['nonce']}"] = cmd['hmac']

        if overwrite:

            cmd = overwrite

        print(f"To Server{cmd}")

        self.nonce+=1

        self.send_message({

            'msg_type': "secure_data_ack",

            'src': self.mitm_addr,

            'dst': self.slf_addr,

            'encrypted': crypto.encrypt(json.dumps(cmd), self.dh_key_shared)

            })

  

    def process_secure_data_response(self, msg, overwrite=None, send=True):

        cmd = json.loads(crypto.decrypt(msg, robot.dh_key_shared).decode())

        print(f"COMMMAND: {cmd}")

        if not 'secure_data_response' in self.hmacs.keys():

            self.hmacs['secure_data_response'] = {}

        self.hmacs['secure_data_response'][f"{cmd['nonce']}"] = {cmd['hmac']: cmd['message']}

        if overwrite:

            cmd = overwrite

        print(f"To Server{cmd}")

        self.nonce += 1

  

        if send:

            self.send_message({

                'msg_type': "secure_data_response",

                'src': self.mitm_addr,

                'dst': self.slf_addr,

                'encrypted': crypto.encrypt(json.dumps(cmd), self.dh_key_shared)

                })

  
  
  
  
  

class Robot(Target):

    def __init__(self):

        super().__init__(16, 31)

  

        self.nonce = 0

  

    def mv_addr(self, new_addr, src_addr):

        self.send_message({

            "msg_type": "set_addr",

            "src": src_addr,

            "dst": self.slf_addr,

            "new_addr": new_addr

        })

        self.slf_addr = new_addr

  

    def send_secure_msg(self, msg_type, data):

        self.send_message({

            'msg_type': msg_type,

            'src': self.mitm_addr,

            'dst': self.slf_addr,

            'encrypted': crypto.encrypt(json.dumps(data), self.dh_key_shared)

            })

        self.nonce += 1

        print(f"🤖 To Robot Controller 🤖 {data}")

  

    def key_exchange(self, key):

        self.dh_key_shared = monocypher.key_exchange(self.dh_key_priv, bytes.fromhex(key))

  
  

robot = Robot()

robot.mv_addr(0x11, 0x20)

# start_robot()

# time.sleep(2)

server = Server(robot)

  

def process_msg(msg_type, buffer):

    msgs, buf = [], []

    msg = None

    buffer += receive_radio_messages()

    for cmd in buffer:

        (buf, msgs)[cmd['msg_type'] == msg_type].append(cmd)

  

    if len(msgs) < 1:

        print(f"Program in unstable state [{msg_type}]. Exiting.")

        #sys.exit(0)

    elif len(msgs) > 1:

        msg = msgs.pop(0)

        buf += msgs

    else:

        msg = msgs[0]

  

    return msg, buf

  

def send_packet(buffer):

    cmd, buffer = process_msg('secure_data', buffer)

    if cmd is not None:

        server.process_secure_data(cmd['encrypted'])

    time.sleep(.75)

  

    cmd, buffer = process_msg('secure_data_ack', buffer)

    if cmd is not None:

        server.process_secure_data_ack(cmd['encrypted'])

    time.sleep(.75)

    cmd, buffer = process_msg('secure_data_request', buffer)

    if cmd is not None:

        server.process_secure_data_request(cmd['encrypted'])

    time.sleep(.75)

  

    cmd, buffer = process_msg('secure_data_response', buffer)

    if cmd is not None:

        server.process_secure_data_response(cmd['encrypted'])

    time.sleep(.75)

    time.sleep(.75)

    print(f"{'-'*20}\n{buffer}\n{'-'*20}")

  

    return buffer

  

start_robot()

time.sleep(.5)

buffer = []

cmd, buffer = process_msg('validate', buffer)

server.validate_robot(cmd['challenge'])

time.sleep(.75)

  

cmd, buffer = process_msg('ack_validate', buffer)

server.ack_validate_robot(cmd['response'])

time.sleep(.75)

  

cmd, buffer = process_msg('key_exchange', buffer)

server.key_exchange(cmd['key'])

time.sleep(.75)

  

cmd, buffer = process_msg('ack_key_exchange', buffer)

robot.key_exchange(cmd['key'])

time.sleep(.75)

  
  

###########################################################################################################>>>

# Robot to Flag: e1, s3, e5, n7, w9, s11, e13, n15, e17, s19

# In nomal steps, can get e1, s3, n7, s11, n15, e17, s19. Missing e5, w9, e13

# Run each phase below by relaunching the instance to get different port number. Remember to comment other phases.

  

"""

# Phase 1: Get the hmacs.json table.

for i in range(1,20):

    buffer = send_packet(buffer)

  

with open("hmacs.json", "w") as file:

    file.write(json.dumps(server.hmacs))

  

## check the output. Find the messages for e1, s3, n7, s11, n15, e17, s19 such as:

## {'message': 'east', 'nonce': 1, 'hmac': '4d10e4ca658dd36b4029b8f7ee39970b436857521750617c6fe38b72d31570567ae452609e9678278c82b6fdcf597e0a42f690c4e328e76cdcfa0bb29f998c79'}

## {'message': 'south', 'nonce': 3, 'hmac': '812b32ae80fafa2637484192f257020ad69fb5f8f658191ed5ca8061bb32fdc33f965189bb2a9f91968a6f0123ff645cf8a97f14e068fa0dfaaeb63bb999c7ac'}

## {'message': 'north', 'nonce': 7, 'hmac': 'df33b3c0db7aa18e2f70a0e855b6385205bfe70414e7e56d34712fe03b9690437a7dcde5cb2e468b8a1e3bae45c246ef001826cdedfc4877737f90effe6ecda5'}

## {'message': 'south', 'nonce': 11, 'hmac': 'd761cd6de5939dbe3bb33f3d972939d7c487b84037c51e214f9ddf2329d736df0101f1403ac06ad65ef69d1806ded0d6f37c144fd3c1a6770388f069592fc633'}

## {'message': 'north', 'nonce': 15, 'hmac': '5c3d05468305391419a15726b84a79d5ebbf8a5c67e5ae404121016f2065214f735d58ff2b417502fa76a8f4233ad7d1d4f5499bfed55d01554d3c891bc94c82'}

## {'message': 'east', 'nonce': 17, 'hmac': '57f51f185a622c9672de3aa40b7a909670a4ee92d9f3cbd1f6c256b1e327ef7a78b68f655a6cd095996c9f3791a20250588d398d0ca0af8cf71ea09beff6f552'}

## {'message': 'south', 'nonce': 19, 'hmac': '854e6fd37c15f26e11517c255fb10401527c9bd397ac3cfe4d3e5260ae0c728bdf3fa45c5667cf0da9b48d5d9d1305e6ba30dc8a168056aa55212055cd1d2b80'}

  

# restart the instance. Comment phase 1 and start do phase 2.

  
  

# Phase 2,3,4 all use below code

with open('hmacs.json', 'r') as file:

    data = json.load(file)

  

def move_robot_nonce(mov, nonce, buffer):

    print(f"{'-'*40}Moving {mov} nonces{'-'*40}")

    for i in range(nonce, mov+nonce):

        print(f"{'-'*40}{i}{'-'*40}")

        robot.send_secure_msg('secure_data_request',{'message': '', 'nonce': i, 'hmac': data['secure_data_blank'][f'{i}']})

        time.sleep(.75)

        cmd, buffer = process_msg('secure_data_response', buffer)

        if cmd is not None:

            server.process_secure_data_response(cmd['encrypted'], send=False)

    return buffer

  

def get_forged_packet(nonce, move_hmac, buffer):

#1

    print('\n----------------#1--------------------\n')

    msg = {'message': 'get_movement', 'nonce': nonce, 'hmac': move_hmac}

    cmd, buffer = process_msg('secure_data', buffer)

    if cmd is not None:

        server.process_secure_data(cmd['encrypted'], overwrite=msg)

    time.sleep(.75)

  

    cmd, buffer = process_msg('secure_data_ack', buffer)

    if cmd is not None:

        server.process_secure_data_ack(cmd['encrypted'])

    time.sleep(.75)

  

    msg2 = {'message': '', 'nonce': (nonce+1), 'hmac': data['secure_data_blank'][f'{nonce+1}']}

    print (msg2)

    cmd, buffer = process_msg('secure_data_request', buffer)

    #if cmd is not None:

    server.process_secure_data_request(None, overwrite=msg2)

    time.sleep(.75)

  

    cmd, buffer = process_msg('secure_data_response', buffer)

    if cmd is not None:

        server.process_secure_data_response(cmd['encrypted'])

    time.sleep(.75)

  

    return buffer

  
  

# Phase 2: get East5:

buffer = move_robot_nonce(4,0,buffer)

buffer = get_forged_packet(4, '0d2efd565d262ef2bca3fcfc21ca4986f7b05371af6b29c69f9bc1f6c35df9ece60f610fa821c440c89f93f2477e9bde0488767c1ad947f573d4f930ee54f272', buffer)

## In the output find something like this: {'message': 'east', 'nonce': 5, 'hmac': '641f430966252586edd46abf183707a1ed547af919df4ae5ccb3d99c8de3bf6ee73f17badee33e2ee2cd8389f471713138855ec74f76b65b58ed35f04c86d4ec'}

## restart the instance. Comment out and do phase 3.

  
  

# Phase 3: get west9

buffer = send_packet(buffer)

buffer = send_packet(buffer)

buffer = move_robot_nonce(4,4,buffer)

# copy the hmac from secure_date with nonce=8 in the hmacs.json file

buffer = get_forged_packet(8, '234b447db10bf160867ebf3ecaa5b9d2bc4984fbc9f98ae8954ea0a292ec1a1c6a4472f50c1e44ed370f006667ad58892e9a14848908bcd0687f96045c7c2ae3', buffer)

## In the output find something like this: {'message': 'west', 'nonce': 9, 'hmac': 'a7dfbfa1a6409b35abe300e0eadd0443b1a43314c1b07cb2cf2131dc210ac5050c7a0aee7133c314bfabdfacbcfb80609f957fac8ffb253bed9588963dc1433f'}

  
  

# Phase 4: get east13

buffer = move_robot_nonce(12,0,buffer)

# copy the hmac from secure_date with nonce=12 in the hmacs.json file

buffer = get_forged_packet(12, '6ff80a5e7420da9d450786560539d40fe318b5b2e5878933e71663cda91d5aa5e9bd818820ffec7f3cb8f98190514aab59408eedcda754011a2323306690871a', buffer)

## In the output find something like this: {'message': 'east', 'nonce': 13, 'hmac': '4e99fcbdbdbd6727bb2bea5ec844d704d7af016ecd81656b0c08baa21ab94f5a76e85659cd408507152583368a9f604fd2dcfc26514b546e10da9631c4018ab7'}

  

 """

# Phases 1,2,3,4 Done

##################################################################################################################<<<

  
  

# Final Step: ^_^ Control robot to go to the flag

moves = [

{'message': 'east', 'nonce': 1, 'hmac': '4d10e4ca658dd36b4029b8f7ee39970b436857521750617c6fe38b72d31570567ae452609e9678278c82b6fdcf597e0a42f690c4e328e76cdcfa0bb29f998c79'},

{'message': 'south', 'nonce': 3, 'hmac': '812b32ae80fafa2637484192f257020ad69fb5f8f658191ed5ca8061bb32fdc33f965189bb2a9f91968a6f0123ff645cf8a97f14e068fa0dfaaeb63bb999c7ac'},

{'message': 'east', 'nonce': 5, 'hmac': '641f430966252586edd46abf183707a1ed547af919df4ae5ccb3d99c8de3bf6ee73f17badee33e2ee2cd8389f471713138855ec74f76b65b58ed35f04c86d4ec'},

{'message': 'north', 'nonce': 7, 'hmac': 'df33b3c0db7aa18e2f70a0e855b6385205bfe70414e7e56d34712fe03b9690437a7dcde5cb2e468b8a1e3bae45c246ef001826cdedfc4877737f90effe6ecda5'},

{'message': 'west', 'nonce': 9, 'hmac': 'a7dfbfa1a6409b35abe300e0eadd0443b1a43314c1b07cb2cf2131dc210ac5050c7a0aee7133c314bfabdfacbcfb80609f957fac8ffb253bed9588963dc1433f'},

{'message': 'south', 'nonce': 11, 'hmac': 'd761cd6de5939dbe3bb33f3d972939d7c487b84037c51e214f9ddf2329d736df0101f1403ac06ad65ef69d1806ded0d6f37c144fd3c1a6770388f069592fc633'},

{'message': 'east', 'nonce': 13, 'hmac': '4e99fcbdbdbd6727bb2bea5ec844d704d7af016ecd81656b0c08baa21ab94f5a76e85659cd408507152583368a9f604fd2dcfc26514b546e10da9631c4018ab7'},

{'message': 'north', 'nonce': 15, 'hmac': '5c3d05468305391419a15726b84a79d5ebbf8a5c67e5ae404121016f2065214f735d58ff2b417502fa76a8f4233ad7d1d4f5499bfed55d01554d3c891bc94c82'},

{'message': 'east', 'nonce': 17, 'hmac': '57f51f185a622c9672de3aa40b7a909670a4ee92d9f3cbd1f6c256b1e327ef7a78b68f655a6cd095996c9f3791a20250588d398d0ca0af8cf71ea09beff6f552'},

{'message': 'south', 'nonce': 19, 'hmac': '854e6fd37c15f26e11517c255fb10401527c9bd397ac3cfe4d3e5260ae0c728bdf3fa45c5667cf0da9b48d5d9d1305e6ba30dc8a168056aa55212055cd1d2b80'}

]

  
  

for i in range (len(moves)):

    cmd, buffer = process_msg('secure_data', buffer)

    if cmd is not None:

        server.process_secure_data(cmd['encrypted'])

    time.sleep(.75)

  

    cmd, buffer = process_msg('secure_data_ack', buffer)

    if cmd is not None:

        server.process_secure_data_ack(cmd['encrypted'])

    time.sleep(.75)

    cmd, buffer = process_msg('secure_data_request', buffer)

    if cmd is not None:

        server.process_secure_data_request(cmd['encrypted'])

    time.sleep(.75)

  

    cmd, buffer = process_msg('secure_data_response', buffer)

    if cmd is not None:

        server.process_secure_data_response(cmd['encrypted'], overwrite=moves[i])

    time.sleep(.75)

    time.sleep(2)

  
  
  

time.sleep(1)

stop_robot()

  

receive_radio_messages()

print(json.dumps(server.hmacs))
```

Based on the radio_interface.py, we added one Target class and two subclasses: Server and Robot and corresponding functions. There are several phases. When you run the phase one. Please comment the other phases. Same for other phases. Detailed run guideline in the code. 

Finally we got the flag. picoCTF{r1gh7_84ck_47_y4_7d7f8bb2}

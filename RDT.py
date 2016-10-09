import Network
import argparse
from time import sleep
import time
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S
        
class Packet_2:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32
    ack_length = 1 
        
    def __init__(self, seq_num, msg_S, ack):
        self.seq_num = seq_num
        self.msg_S = msg_S
        self.ack = ack
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet_2.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        ack = int(byte_S[Packet.length_S_length+Packet.seq_num_S_length:Packet.length_S_length+Packet.seq_num_S_length+Packet_2.ack_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length+Packet_2.ack_length :]
        return self(seq_num, msg_S, ack)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        ack_S = str(self.ack)
        
        checksum = hashlib.md5((length_S+seq_num_S+ack_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + ack_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        ack_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length: Packet.seq_num_S_length+Packet.seq_num_S_length+Packet_2.ack_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet_2.ack_length : Packet.seq_num_S_length+Packet.length_S_length+Packet_2.ack_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length+Packet_2.ack_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5((length_S+seq_num_S+ack_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        #print('Packet checked for corruption')
        #print(length_S+seq_num_S+ack_S+checksum_S+msg_S)
        #print()
        
        return checksum_S != computed_checksum_S


class RDT:
    ## latest sequence number used in a packet
    seq_num = 0
    ## buffer of bytes read from network
    byte_buffer = '' 

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()
        
    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration
            
    
    prior_message = None
    
    def rdt_2_1_send(self, msg_S):
        
        #Save the old message for re-transmission
        self.prior_message = msg_S
        print('Calling RDT 2.1 Send')
        p = Packet_2(self.seq_num, msg_S, 2)    
        
        #print('Sending data packet')
        #print(p.get_byte_S())
        #print()
        #Do not increment sequence number till receiving an ACK
        self.network.udt_send(p.get_byte_S())
        
    def rdt_2_1_send_response(self, response):
        p = None
        if response == 1:
            p = Packet_2(self.seq_num, 'ACK', response)
        else:
            p = Packet_2(self.seq_num, 'NAK', response)
        self.network.udt_send(p.get_byte_S())     
        
    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        
        while True:
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S
            
            length = int(self.byte_buffer[:Packet.length_S_length])+1
            if len(self.byte_buffer) < length:
                return ret_S
            
            try:
                p = Packet_2.from_byte_S(self.byte_buffer[0:length])
            except RuntimeError:
                print('Packet is corrupt')
                print('Sending NAK')
                self.byte_buffer = self.byte_buffer[length:]
                self.rdt_2_1_send_response(0)#NAK
                break
            
            #Check packet type
            if p.ack == 2: #Data packet and not corrupt, send ACK
                print('Received data packet')
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                self.byte_buffer = self.byte_buffer[length:]
                print('Sending ACK')
                self.rdt_2_1_send_response(1)#ACK
            elif p.ack == 1:#ACK packet
                print('Received ACK packet')
                self.byte_buffer = self.byte_buffer[length:]
                self.seq_num += 1
                break
            elif p.ack == 0:#NAK packet
                print('Received NAK packet')
                self.byte_buffer = self.byte_buffer[length:]
                self.rdt_2_1_send(self.prior_message)
                break
    
    timeout = 0.5 #1 second timeout
    time_last_send = None
    checkTime = False
    
    def rdt_3_0_send(self, msg_S):
        #Save the old message for re-transmission
        self.prior_message = msg_S
        #print('Calling RDT 3.0 Send')
        #print('MESSEGE: '+msg_S)
        p = Packet_2(self.seq_num, msg_S, 2)  
        
        #Set the time of the send      
        self.checkTime = True
        self.network.udt_send(p.get_byte_S())
        self.time_last_send = time.time()
        
        if self.seq_num == 0:
            self.seq_num = 1
        else:
            self.seq_num = 0
      
    def rdt_3_0_send_response(self, response):
        p = None
        if response == 1:
            p = Packet_2(self.seq_num, 'ACK', response)
        else:
            p = Packet_2(self.seq_num, 'NAK', response)
            
        self.checkTime = False    
        self.network.udt_send(p.get_byte_S())    
        
    def rdt_3_0_receive(self):
        current_time = time.time()
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        
        while True:
            
            #If timeout occured, resend message
            if(self.time_last_send != None and self.checkTime):
                if current_time - self.time_last_send > self.timeout:
                    #print('Timeout occured')
                    self.rdt_3_0_send(self.prior_message)
            
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S
            
            length = int(self.byte_buffer[:Packet.length_S_length])+1
            if len(self.byte_buffer) < length:
                return ret_S
            
            try:
                p = Packet_2.from_byte_S(self.byte_buffer[0:length])
                #print('Sequence Num')
                #print(self.seq_num)
            except RuntimeError:
                #print('Packet is corrupt')
                self.byte_buffer = self.byte_buffer[length:]
                #self.rdt_3_0_send_response(0)#NAK
                break
            
            #Check packet type
            if p.ack == 2: #Data packet and not corrupt, send ACK
                #print('Received data packet')
                self.old_seq_num = p.seq_num
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                self.byte_buffer = self.byte_buffer[length:]
                #print('Sending ACK')
                self.rdt_3_0_send_response(1)#ACK
            elif p.ack == 1 and p.seq_num == self.seq_num:#ACK packet
                #print('Received ACK packet')
                self.byte_buffer = self.byte_buffer[length:]
                self.checkTime = False
                break
            else:
                self.byte_buffer = self.byte_buffer[length:]
                break
        

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        
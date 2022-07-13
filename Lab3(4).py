#Lab 3 - Juan Molina, Eric Pan, Yazdan Rahman

import socket
import argparse
import threading
import os
import json

from service_announcement import Server as discoveryServer #Code Retrieved from Class Notes
from service_discovery_cycles import Client as discoveryClient #Code Retrieved from Class Notes


#Definitions for the packet protocol field lengths
CMD_LENGTH = 1 #All commands as specified are 1 byte
FILE_SIZE_LENGTH = 8 #The file syze can be up to 8 bytes
FILE_NAME_LENGTH = 127 
PACKET_SIZE_LENGTH = 8
CMD = { "PUT": 1, "GET": 2, "SCAN": 3, "CONNECT": 4, "LLIST": 5, "RLIST": 6, "BYE": 7 } #All Commands possible
ENCODING = "utf-8"

#######################################################Server#########################################################

class Server:

    HOSTNAME = "127.0.0.1"
    PORT = 50001
    RECV_SIZE = 1024
    MAX_BACKLOG = 10
    
    DIR = "/home/dn4/4DN4/Lab/Server Dir"
    
    def __init__ (self):
    #Starts the discovery server thread
        self.discovery_server = None
        self.discovery_thread = threading.Thread (target = self.create_discovery_server)
        self.discovery_thread.start()
        
        self.create_listen_socket() #Bound TCP socket to listening state
        
        print("\nFiles in specified directory:")
        
        for x in os.listdir(Server.DIR):#Change what's in brackets if files in different directory
            print(x) #Simply runs through the directory we specified and prints all the items
        
        self.process_connections_forever() #Keeps server operating
        
####################################################################################################################        
        
    def create_discovery_server(self): #Creates discovery server to continually listen for UDP packets
        self.discovery_server = discoveryServer()
        
####################################################################################################################
    
    def create_listen_socket(self): #The usual way to create a liten socket
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((Server.HOSTNAME, Server.PORT))
            self.socket.listen(Server.MAX_BACKLOG)
            print("Listening on for file sharing connections on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            exit()    
            
###################################################################################################################### 
           
    def process_connections_forever(self):
        try:
            while True:
                self.connection_handler(self.socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            
###################################################################################################################### 
            
    def connection_handler(self, client):    
        
        connection, addrPort = client
        print("-" * 72)
        print(f"Connection received with {addrPort[0]} on port {addrPort[1]}.")
        
        while True:
            recvd = connection.recv(CMD_LENGTH)
            
            if len (recvd) == 0:
                print("Connection ended by client.")
                connection.close()
                return
        
            cmd = int.from_bytes(recvd, byteorder='big') #Network byte order
            print(cmd)
            if cmd == CMD["GET"]:
                print("Received: GET command.\n")
                recvBytes = connection.recv(Server.RECV_SIZE)
                recvString = recvBytes.decode(ENCODING)
                print(recvString)
                packet = self.get_file(recvString, connection) #Recv_String is the filename on the server's directory
                
            elif cmd == CMD["RLIST"]:
                print("Received: RLIST command.\n")
                packet = self.list_directory()
        
            elif cmd == CMD["PUT"]:
                print("Received: PUT command.\n")
                recvBytes = connection.recv(Server.RECV_SIZE)
                packet = self.put_file(recvBytes, connection) #Recv_bytes are the bytes from the file we need to upload  

            try:#Will try to send the packet to the connected client
                if packet != None:
                    connection.sendall(packet)
               
            except socket.error: #If the client closes the connection before the upload finishes, the connection will close
                print("Package could not be uploaded because client closed their connection early... ")
                connection.close()
                return                
                      
######################################################################################################################  
          
    def get_file(self, fileName, connection): #Opens the file requested and sends it to client
        try:
            if(fileName[-3:] == "mp3" or fileName[-3:] == "png"):
                
                file = open(f"{Server.DIR}/{fileName}", "rb").read()
            else:
                
                file = open(f"{Server.DIR}/{fileName}", "r").read()

        except FileNotFoundError:
            print("ERROR: The file requested cannot be found in the directory!")
            connection.close()
            return

        if(fileName[-3:] == "mp3" or fileName[-3:] == "png"):
            print("Downloading MP3...")
            fileBytes = file #Encodes the contents of the file into bytes
        else:
            print("Downloading file...")
            fileBytes = file.encode(ENCODING) #Encodes the contents of the file into bytes            
        
        fileSizeBytes = len(fileBytes) #Size of file in bytes
        fileSizeField = fileSizeBytes.to_bytes(FILE_SIZE_LENGTH, byteorder = "big") #File Size field used for transmission

        return fileSizeField + fileBytes #Sends back the field size used for transmission and the encoded bytes
        
    
######################################################################################################################   
          
    def list_directory(self): #Will read the contents of the directory and will list them out on cmd
        contents = os.listdir(Server.DIR)
        packetString = ""
        
        print(contents)
        
        for x in contents:
            packetString +=  f"{x}\n" #Appends each item to the packet string that contains all file names
            
        packetBytes = packetString.encode(ENCODING)
        packetByteSize = len(packetBytes)
        packetFieldSize = packetByteSize.to_bytes(PACKET_SIZE_LENGTH, byteorder="big") #Converting int to bytes in network byte order
        
        return packetFieldSize + packetBytes #Sends back the packetFieldSize used for transmission and the encoded packet bytes containing the list of the directory
    
######################################################################################################################   
          
    def put_file(self, packetBytes, connection): #Uploads the file onto server's directory
        fileName = packetBytes[:FILE_NAME_LENGTH].decode(ENCODING).rstrip() 
        fileSize = int.from_bytes(packetBytes[FILE_NAME_LENGTH:(FILE_NAME_LENGTH + FILE_SIZE_LENGTH)], byteorder="big")
        contents = bytearray(packetBytes[(FILE_NAME_LENGTH + FILE_SIZE_LENGTH):])
        
        while(len(contents) < fileSize): #Will keep looping until the whole file is uploaded
            recvd = connection.recv(Server.RECV_SIZE)
            contents += recvd #Contents get updated until length of contents = fileSize. Then we know the whole file uploaded
            
            if (len(recvd) == 0):
                print("There was an error while receiving the file\n Connection Closing....\n")
                connection.close()
                return
                
        try:
            with open(f"{Server.DIR}/{fileName}", "w") as f:
                f.write(contents.decode(ENCODING)) #Write the contents in of the file
            print(f"Received file successfully: {fileName}")
        except Exception as msg:
            print(f";/'Error when writing the following file {fileName}: {msg}")
                    
######################################################################################################################

class Client:
    
    RECV_SIZE = 10
    DIR = "/home/dn4/4DN4/Lab/Client Dir"
    
    def __init__(self):
        print("1")
        self.get_socket()
        print("2")
        self.discovery_client = discoveryClient()
        print("3")
        self.main()
        
######################################################################################################################
        
    def main(self):
         while True:
            cmd, args = self.get_input()

            if cmd == CMD["PUT"]: #Put file from client dir to server dir
                self.put_file(args[0])
                    
            elif cmd == CMD["GET"]: #Get "filename" and saves file locally
                self.get_file(args[0])

            elif cmd == CMD["SCAN"]:
                self.discovery_client.scan_for_service() #Uses scan for service from file supplied
                
            elif cmd == CMD["CONNECT"]: #Connect to the file sharing service at address ...
                self.connect_to_server()
                    
            elif cmd == CMD["LLIST"]: #Output local directory listing of its local file directory
                self.get_local_list()
                    
            elif cmd == CMD["RLIST"]: #Sent command to server to obtain a file sharing discovery list.
                self.get_remote_list()
                
            elif cmd == CMD["BYE"]: #Close connection
                self.close_connection()
                return
                
 ######################################################################################################################       
   
    def get_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            exit()
 
 ######################################################################################################################

    def connect_to_server(self, ip=Server.HOSTNAME, port=Server.PORT):
        try:
            self.socket.connect((ip, port))
            print(f"Connected to server at {ip}:{port}\n")
        except Exception as msg:
            print(msg)
            exit() 
            
 ######################################################################################################################
 
    def socket_recv_size(self, length):
        bytes = self.socket.recv(length)
        if len(bytes) < length:
            self.socket.close()
            exit()
        return(bytes)
       
######################################################################################################################
 
    def get_input(self):
        while True:
            userInput = input("Enter a command: ")
            print("")
            args = userInput.split(" ") #Gets the separate args, Needed
            
            if len(args) > 1:
                userInput = args[0]
                args = args[1:]
            else:
                args = []
                
            userInput = userInput.upper() #CMD command sent to uppercase
            
            for string, cmdByte in CMD.items(): #Searches to see if the command sent is actually within our dictionary
                if userInput == string: 
                    return cmdByte, args #If so sends back CMD and argument
            
            print("The command entered cannot be found. Please Try Again!\n")
        
 ######################################################################################################################        
                
    def get_local_list(self):
        for item in os.listdir(Client.DIR):
            print(item) #Runs through the client directory and outputs the files there 
        
        print("")
        
 ######################################################################################################################        
        
    def get_file(self, remoteFilename, localFilename=None):
        

        if localFilename == None:
            localFilename = remoteFilename
        
        
        getField = CMD["GET"].to_bytes(CMD_LENGTH, byteorder='big')#Makes GET field
        filenameField = remoteFilename.encode(ENCODING) #Makes filename field
        packet = getField + filenameField  #Creates the packet.
        print(packet)
        self.socket.sendall(packet)#Sends the request packet to the server

        fileSizeBytes = self.socket_recv_size(FILE_SIZE_LENGTH)#Read the file size field.
        if len(fileSizeBytes) == 0:
            self.socket.close()
            return

        fileSize = int.from_bytes(fileSizeBytes, byteorder='big') #Host Byte order
        
        recvdBytes = bytearray()
        try:
            while len(recvdBytes) < fileSize: #Need to keep receiving until the receivedBytes is equal to the filesize we needed to download
                recvdBytes += self.socket.recv(Client.RECV_SIZE)

            print("Received {} bytes. Creating file: {}" \
                    .format(len(recvdBytes), localFilename))
            #print(localFilename[-3:])
            if(localFilename[-3:] == "mp3" or localFilename[-3:] == "png"):
                "Downloading MP3 file..."
                with open(f"{Client.DIR}/{localFilename}", 'wb') as f: #Creates a new file using the filename received
                    f.write(recvdBytes)
            
            else:
                "Downloading file..."
                with open(f"{Client.DIR}/{localFilename}", 'w') as f: #Creates a new file using the filename received
                    f.write(recvdBytes.decode(ENCODING))
                
        except KeyboardInterrupt:
            exit(1)
            
        except socket.error: #If the server socket closes, this one will close too
            self.socket.close()    
        
######################################################################################################################         
        
    def put_file(self, localFilename, remoteFilename=None): #Just like get function from server
        if remoteFilename == None:
            remoteFilename = localFilename
        try:
            with open(f"{Client.DIR}/{localFilename}", "r") as f: 
                fileBytes = f.read().encode(ENCODING) #Encodes contents into bytes
                fileSizeBytes = len(fileBytes) #Record its file size
                fileSizeField = fileSizeBytes.to_bytes(FILE_SIZE_LENGTH, byteorder='big') #Host Byte order
                filenameField = remoteFilename.ljust(FILE_NAME_LENGTH).encode(ENCODING)
                packet = CMD["PUT"].to_bytes(CMD_LENGTH, byteorder='big') + filenameField + fileSizeField + fileBytes #Creates whole packet
                
                self.socket.sendall(packet)
                return None
            
        except FileNotFoundError:
            print("Sorry! The file specified cannot be found!!!")            
            return    
        
######################################################################################################################   

    def get_remote_list(self):
        packet = CMD["RLIST"].to_bytes(CMD_LENGTH, byteorder='big')
        self.socket.sendall(packet)
        
        listSizeBytes = self.socket_recv_size(PACKET_SIZE_LENGTH)
        listSize = int.from_bytes(listSizeBytes, byteorder='big')
        
        if len(listSizeBytes) == 0: #If theres nothing to copy it will just close the connection
            self.socket.close()
            return

        recvdBytes = bytearray()
        while(len(recvdBytes) < listSize):
            recvdBytes += self.socket.recv(Client.RECV_SIZE) #Receive the bytes with the info

        recvdstring = recvdBytes.decode(ENCODING)
        print(recvdstring)      
        
###################################################################################################################### 
        
    def close_connection(self):
        self.socket.close()
        print("Closed connection.")    
        
######################################################################################################################         

if __name__ == '__main__':
    roles = {'server': Server, 'client': Client}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

#####################################################################################################################         
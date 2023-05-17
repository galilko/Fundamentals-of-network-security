# Gal Gabay 207006024
# Yechezkel Chen 325191419
# Mini-Project Video Spyware

import re
import subprocess
import socket


class SpeedTestResults:
	"""
	The SpeedTestResults class is used to get the internet connection speedtest results including
	ping, download and upload speeds.
	"""
	def __init__(self):
		"""
		Initializes the class with default values of 0 for ping, download and upload.
		"""
		self.ping = 0
		self.download = 0
		self.upload = 0

	def check_connection(self):
		"""
		A method that check the internet connection.
		"""
		try:
			socket.create_connection(("www.google.com", 80))
			return True
		except OSError:
			pass
		return False

	def get_results(self):
		"""
		A method that returns the internet connection speedtest results including
		ping, download and upload speeds.
		"""
		if self.check_connection():
			response = str(subprocess.Popen('speedtest-cli --simple', shell=True, stdout=subprocess.PIPE).stdout.read())
			ping = re.findall('Ping:\s(.*?)\s', response, re.MULTILINE)
			download = re.findall('Download:\s(.*?)\s', response, re.MULTILINE)
			upload = re.findall('Upload:\s(.*?)\s', response, re.MULTILINE)

			self.ping = ping[0].replace(',', '.')
			self.download = download[0].replace(',', '.')
			self.upload = upload[0].replace(',', '.')

			return str(float(self.download)/8), str(float(self.upload)/8), str(float(self.ping)/8)
		else:
			print("No Internet Connection!")
			return None, None, None

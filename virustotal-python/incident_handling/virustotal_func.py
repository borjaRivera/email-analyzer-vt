from base64 import urlsafe_b64encode
from virustotal_python import Virustotal

API_KEY = "a1e4a0a46cd1ea3c807598d68d85281e130af36bd5452ff917c46be7dd4e3b57"

"""FUNCTIONALITIES"""

class VirusTotalFunc:

	def get_file_info(id):
		vtotal = Virustotal(API_KEY=API_KEY)
		resp = vtotal.request(f"files/{id}")

		return resp.data


	def scan_url(url):
		vtotal = Virustotal(API_KEY=API_KEY)
		resp = vtotal.request("urls", data={"url": url}, method="POST")
		# Safe encode URL in base64 format
		# https://developers.virustotal.com/reference/url
		url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
		#print(f"URL: {url} ID: {url_id}")
		report = vtotal.request(f"urls/{url_id}")

		return report.data
	

	def scan_ip(ip):
		vtotal = Virustotal(API_KEY=API_KEY)
		# Get information about an IP address
		resp = vtotal.request(f"ip_addresses/{ip}")

		return resp.data
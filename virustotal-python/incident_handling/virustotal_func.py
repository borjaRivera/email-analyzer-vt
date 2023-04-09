from base64 import urlsafe_b64encode
from virustotal_python import Virustotal
import yaml

with open("../config.yml") as f:
	content = f.read()
	
# from credentials.yml import user name and password
content_details = yaml.load(content, Loader=yaml.FullLoader)

#Load the user name and passwd from yaml file
API_KEY = content_details["VT_API_KEY"]



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
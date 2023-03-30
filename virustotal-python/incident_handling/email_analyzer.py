from base64 import urlsafe_b64encode
import datetime
from virustotal_python import Virustotal

import email
import re
import hashlib
import json
import urllib
from urllib.request import urlopen
import time
import argparse
from pprint import pprint

API_KEY = "a1e4a0a46cd1ea3c807598d68d85281e130af36bd5452ff917c46be7dd4e3b57"


"""ESENCTIAL FUNCTIONS"""

def init():
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--file", nargs=1, metavar='filename',
		help="File to process.")
	parser.add_argument("-o", "--output", nargs=1,
		help="Output.")
	parser.add_argument("-vt", "--virustotal", action='store_true',
		help="Skip virustotal chekings.")
	args = parser.parse_args()
	return args


def unique(seq):
	seen = set()
	seen_add = seen.add
	return [ x for x in seq if x not in seen and not seen_add(x)]


def get_ip_addresses(email_message):
	ip_addresses = []
	for header in email_message.items():
		ip = re.search(r'((2[0-5]|1[0-9]|[0-9])?[0-9]\.){3}((2[0-5]|1[0-9]|[0-9])?[0-9])', header[1], re.I)
		if ip:
			ip=ip.group()
			ip_addresses.append(ip)
	return unique(ip_addresses)


def recursive(payload):
	for i in payload:
		if i.get_content_maintype() == "multipart":
			mail = i.get_payload()
			body = recursive(mail)
			return body
		elif i.get_content_maintype()  == "text":
			return i.get_payload()


def get_body(email_message):
	maintype = email_message.get_content_maintype()
	payload = email_message.get_payload()
	if maintype == "multipart":
		body = recursive(payload)
	elif maintype == "text":
		body = email_message.get_payload()
	return body


def get_links(body):
	links = []
	regex = re.compile(r'http.+\.[0-9a-zA-Z\-\_\/\%\&\|\\\+\=\?\(\)\$\!]+\.[0-9a-zA-Z\-\_\/\%\&\|\\\+\=\?\(\)\$\!\:]+')
	linksaux = regex.findall(body)
	for link in linksaux:
		if link.find(' ') == -1 and link.find('\t') == -1:
			links.append(link)

	return unique(links)


def get_attachments(email_message):
	payload = email_message.get_payload()
	attachments = []
	for section in payload:
		try:
			section.get_filename()
			if section.get_filename() != None:
				attachment = {}
				attachment['filename'] = section.get_filename()
				#print("filename: ", attachment['filename'] )

				attachment['type'] = section.get_content_type()
				#print("type: ", attachment['type']  )

				attachment['file'] = section.get_payload(decode=True)
				#print("file: ", attachment['file']  )

				sha1 = hashlib.sha1(attachment["file"]).hexdigest()
				attachment['sha1'] = sha1
				#print("sha1: ", attachment['sha1']  )

				hashmd5 = hashlib.md5(attachment["file"]).hexdigest()
				attachment['hashmd5'] = hashmd5
				#print("md5: ", attachment['hashmd5']  )

				attachments.append(attachment)
		except:
			pass
			#print("File hash not found in VirusTotal")
	return attachments


def analyze_attachment(file_to_analyze):
	try:
		response = get_file_info(file_to_analyze)
		malicious = response['attributes']['last_analysis_stats']['malicious']
		undetected = response['attributes']['last_analysis_stats']['undetected']
		total = malicious + undetected
		print("\tVT Detections: %d/%d" % (malicious, total))
	except Exception as e:
		print("\tVT: File hash not found in VirusTotal")


def analyze_url(url_to_analyze):
	try:
		response = scan_url(url_to_analyze)
		malicious = response['attributes']['last_analysis_stats']['malicious']
		suspicious = response['attributes']['last_analysis_stats']['suspicious']
		undetected = response['attributes']['last_analysis_stats']['undetected']
		timeout = response['attributes']['last_analysis_stats']['timeout']
		harmless = response['attributes']['last_analysis_stats']['harmless']
		
		print("\t\t[*] VT analysis:")

		print("\t\t\t[*] Detections:",malicious,"malicious, ",
								suspicious,"suspicious,",
								undetected,"undetected,",
								timeout,"timeout,",
								harmless,"harmeless")
		
		last_analysis_date = datetime.datetime.fromtimestamp(response['attributes']['last_analysis_date'])
		print("\t\t\t[*] Last analysis date: ", last_analysis_date)
		
		first_submission_date = datetime.datetime.fromtimestamp(response['attributes']['first_submission_date'])
		print("\t\t\t[*] First submission date: ", first_submission_date)

	except Exception as e:
		print("\t\t\tNot found in VirusTotal", e)


def output_console(frm, to, cc, subject, messageID, headers, ips, 
	links, attachments, args):

	if len(frm) > 0:
		print("\n[*] From:")
		for sender in frm:
			print("\t%s" % (sender) )

	print("\n[*] Receivers:")

	if len(to) > 0:
		print("\t[*] To:")
		for receiver in to:
			print("\t\t%s" % (receiver))

	if len(cc) > 0:
		print("\t[*] Cc:")
		for receiver in cc:
			print("\t\t%s" % (receiver))

	if len(messageID) > 0:
		print("\n[*] Message-ID:")
		for mid in messageID:
			print("\t%s" % (mid))

	if len(subject) > 0:
		print("\n[*] Subject:")
		for sbj in subject:
			print("\t%s" % (sbj))

	""""
	print("[*] Headers:")
	for line in headers:
		print("\t%s: %s" % (line[0], line[1]))

	if len(ips) > 0:
		print("\n[*] IP Addresses:")
		if args.virustotal:
			for ip in ips:
				print(ip)
		else:
			for ip in ips:
				print("\t%s" % (ip[0]))
				if len(ip) > 1:
					for i in ip[1]:
						print("\t\t%s - %d/%d - %s" % (i['url'], i['positives'],
							i['total'], i['scan_date']))
	"""

	if len(links) > 0:
		print("\n[*] Links:")
		for link in links:
			print("\t%s" % (link))

			analyze_url(link)


	if len(attachments) > 0:
		print("\n[*] Attachments:")
		for att in attachments:
			print("\tFile: %s" % (att["filename"]))
			print("\tFile type: %s" % (att["type"]))
			print("\tSHA1: %s" % (att['sha1']))
			print("\tMD5: %s" % (att['hashmd5']))
			
			analyze_attachment(att['sha1'])
				
			print("\n")




"""FUNCTIONALITIES"""

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



"""MAIN"""
def main():
	#res = get_file_info("9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115")
	#pprint(res['attributes']['last_analysis_stats'])

	args = init()

	if args.file:
		try:
			email_message = email.message_from_string(open(args.file[0]).read())
		except Exception as e:
			print("There was an error opening the file %s: %s" % (args.file[0],
				e))
			quit()

	else:
		print("ERROR: You must use the option -f.")
		quit()

	frm = email_message.get_all('from', [])
	to = email_message.get_all('to', [])
	cc = email_message.get_all('cc', [])
	subject = email_message.get_all('subject',[])
	messageID = email_message.get_all('message-ID', [])
	headers = email_message.items()
	ips = get_ip_addresses(email_message)
	links = get_links(get_body(email_message))
	attachments = get_attachments(email_message)

	output_console(frm, to, cc, subject, messageID, headers, ips,
		   links, attachments, args)



if __name__ == '__main__':
	main()
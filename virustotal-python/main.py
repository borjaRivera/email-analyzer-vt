import argparse
import email
from os import walk
import os
import time

from incident_handling.gmail_extractor import GmailExtractor

from incident_handling.email_content_extractor import EmailContentExtractor
from incident_handling.email_content_analyzer import EmailContentAnalyzer

def init():
    
	parser = argparse.ArgumentParser()

	parser.add_argument("-a", "--all", action='store_true', help="get all files from e-mail inbox account and analyze them.")
	parser.add_argument("-f", "--file", nargs=1, metavar='filename', help="analyze a specific file from a path.")
	#parser.add_argument("-o", "--output", nargs=1, metavar='output', help="utput.")
	#parser.add_argument("-vt", "--virustotal", action='store_true', help="Skip virustotal chekings.")

	args = parser.parse_args()

	return args

def print_receivers(to, cc):

	print("\n[*] Receivers:")
	if len(to) > 0:
		print("\t[*] To:")
		for receiver in to:
			print("\t\t%s" % (receiver))

	if len(cc) > 0:
		print("\t[*] Cc:")
		for receiver in cc:
			print("\t\t%s" % (receiver))

def print_sender(frm):
		if len(frm) > 0:
			print("\n[*] From:")
			for sender in frm:
				print("\t%s" % (sender) )

def print_messageID(messageID):
		if len(messageID) > 0:
			print("\n[*] Message-ID:")
			for mid in messageID:
				print("\t%s" % (mid))

def print_subject(subject):
	if len(subject) > 0:
		print("\n[*] Subject:")
		for sbj in subject:
			print("\t%s" % (sbj))

def print_headers(headers):
	print("[*] Headers:")
	
	for line in headers:
		print("\t%s: %s" % (line[0], line[1]))

def print_ips(ips):
	if len(ips) > 0:
		print("\n[*] IP Addresses:")
		for ip in ips:
			print("\t%s" % (ip))
			EmailContentAnalyzer.analyze_ip(ip)

def print_links(links):
	if len(links) > 0:
		print("\n[*] Links:")
		for link in links:
			print("\t%s" % (link))
			EmailContentAnalyzer.analyze_url(link)

def print_attachments(attachments):
	if len(attachments) > 0:
		print("\n[*] Attachments:")
		for att in attachments:
			
			print("\tFile: %s" % (att["filename"]))
			print("\tFile type: %s" % (att["type"]))
			
			# NOTE: Optional MD5
			# print("\tMD5: %s" % (att['hashmd5']))
			# EmailContentAnalyzer.analyze_attachment(att['hashmd5'])
			
			# NOTE: Optional SHA1
			# print("\tSHA1: %s" % (att['sha1']))
			# EmailContentAnalyzer.analyze_attachment(att['sha1'])			

			print("\tSHA256: %s" % (att['sha256']))
			EmailContentAnalyzer.analyze_attachment(att['sha256'])
			
			print("\n")

def output_console(frm, to, cc, subject, messageID, headers, ips, 
	links, attachments):

	print_sender(frm)

	print_receivers(to,cc)

	print_messageID(messageID)

	print_subject(subject)

	#print_headers(headers)

	print_ips(ips)
	
	print_links(links)
	
	print_attachments(attachments)

	
def analyze(email_message):
	frm = email_message.get_all('from', [])
	to = email_message.get_all('to', [])
	cc = email_message.get_all('cc', [])
	subject = email_message.get_all('subject',[])
	messageID = email_message.get_all('message-ID', [])
	headers = email_message.items()
	ips = EmailContentExtractor.get_ip_addresses(email_message)
	links = EmailContentExtractor.get_links(email_message)
	attachments = EmailContentExtractor.get_attachments(email_message)


	output_console(	frm, 
					to, 
					cc, 
					subject, 
					messageID, 
					headers, 
					ips,
		   			links, 
					attachments
					)


def main():
	#res = get_file_info("9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115")

	args = init()

	if args.file:
		try:
			print("\n\n[ANALYZING FILE]", args.file[0])
			email_message = email.message_from_string(open(args.file[0]).read())
			analyze(email_message)

		except Exception as e:
			print("There was an error opening the file %s: %s" % (args.file[0], e))
			quit()

	elif args.all:
		try:
			print("\n\n[ANALYZING ALL FILES]")

			GmailExtractor.extract("ALL", "")

			time.sleep(2)

			path = os.getcwd() + "/tmp"
			
			files_in_directory = next(walk(path), (None, None, []))[2]

			for file in files_in_directory:
				print("\n\n[ANALYZING FILE]", file)
				try:
					email_message = email.message_from_string(open(path + "/" + file).read())
					analyze(email_message)

				except Exception as e:
					print("There was an error opening the file %s: %s" % (file, e))
					quit()
				
		except:
			pass

	


if __name__ == '__main__':
	main()
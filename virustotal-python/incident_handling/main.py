import argparse
import email

from virustotal_func import VirusTotalFunc
from email_extractor import EmailExtractor
from email_analyzer import EmailAnalyzer

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

	"""
	print("[*] Headers:")
	
	for line in headers:
		print("\t%s: %s" % (line[0], line[1]))
    """
	
	if len(ips) > 0:
		print("\n[*] IP Addresses:")
		for ip in ips:
			print("\t%s" % (ip))
			EmailAnalyzer.analyze_ip(ip)
			

	
	if len(links) > 0:
		print("\n[*] Links:")
		for link in links:
			print("\t%s" % (link))
			EmailAnalyzer.analyze_url(link)


	if len(attachments) > 0:
		print("\n[*] Attachments:")
		for att in attachments:
			
			print("\tFile: %s" % (att["filename"]))
			print("\tFile type: %s" % (att["type"]))
			
			print("\tMD5: %s" % (att['hashmd5']))
			EmailAnalyzer.analyze_attachment(att['hashmd5'])
			
			print("\tSHA1: %s" % (att['sha1']))
			EmailAnalyzer.analyze_attachment(att['sha1'])			

			print("\tSHA256: %s" % (att['sha256']))
			EmailAnalyzer.analyze_attachment(att['sha256'])
			
			print("\n")
			

def main():
	#res = get_file_info("9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115")
	#pprint(res['attributes']['last_analysis_stats'])

	args = init()

	if args.file:
		try:
			email_message = email.message_from_string(open(args.file[0]).read())
		except Exception as e:
			print("There was an error opening the file %s: %s" % (args.file[0], e))
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
	ips = EmailExtractor.get_ip_addresses(email_message)
	links = EmailExtractor.get_links(EmailExtractor.get_body(email_message))
	attachments = EmailExtractor.get_attachments(email_message)

	output_console(	frm, 
					to, 
					cc, 
					subject, 
					messageID, 
					headers, 
					ips,
		   			links, 
					attachments, 
					args)


if __name__ == '__main__':
	main()
from contextlib import suppress
import datetime
from virustotal_func import VirusTotalFunc

from pprint import pprint

class EmailAnalyzer:

	def get_basic_analysis(response):
			
			print("\t\t[*] VT analysis:")

			malicious = response['attributes']['last_analysis_stats']['malicious']
			suspicious = response['attributes']['last_analysis_stats']['suspicious']
			undetected = response['attributes']['last_analysis_stats']['undetected']
			timeout = response['attributes']['last_analysis_stats']['timeout']
			harmless = response['attributes']['last_analysis_stats']['harmless']

			print("\t\t\t[*] Detections:",malicious,"malicious, ",
									suspicious,"suspicious,",
									undetected,"undetected,",
									timeout,"timeout,",
									harmless,"harmless")
			
			last_analysis_date = datetime.datetime.fromtimestamp(response['attributes']['last_analysis_date'])
			print("\t\t\t[*] Last analysis date: ", last_analysis_date)
			
			first_submission_date = datetime.datetime.fromtimestamp(response['attributes']['first_submission_date'])
			print("\t\t\t[*] First submission date: ", first_submission_date)


	def get_basic_analysis_ip(response):
		print("\t\t[*] VT analysis:")

		malicious = response['attributes']['last_analysis_stats']['malicious']
		suspicious = response['attributes']['last_analysis_stats']['suspicious']
		undetected = response['attributes']['last_analysis_stats']['undetected']
		timeout = response['attributes']['last_analysis_stats']['timeout']
		harmless = response['attributes']['last_analysis_stats']['harmless']

		print("\t\t\t[*] Detections:",malicious,"malicious, ",
								suspicious,"suspicious,",
								undetected,"undetected,",
								timeout,"timeout,",
								harmless,"harmless")
		
		last_analysis_date = datetime.datetime.fromtimestamp(response['attributes']['last_analysis_date'])
		print("\t\t\t[*] Last analysis date: ", last_analysis_date)
		
		continent =  response['attributes']['continent'] 
		country = response['attributes']['country']
		print("\t\t\t[*] Continent: ", continent)
		print("\t\t\t[*] Country: ", country)


	def analyze_attachment(hash_to_analyze):
		try:
			response = VirusTotalFunc.get_file_info(hash_to_analyze)

			EmailAnalyzer.get_basic_analysis(response)

		except Exception as e:
			print("\t\t[*] VT: File hash not found in VirusTotal")


	def analyze_url(url_to_analyze):
		try:
			response = VirusTotalFunc.scan_url(url_to_analyze)

			EmailAnalyzer.get_basic_analysis(response)

		except Exception as e:
			print("\t\t\tNot found in VirusTotal")


	def analyze_ip(ip_to_analyze):
		try:
			response = VirusTotalFunc.scan_ip(ip_to_analyze)

			EmailAnalyzer.get_basic_analysis_ip(response)

		except Exception as e:
			print("\t\t\tNot found in VirusTotal", e)
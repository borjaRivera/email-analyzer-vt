import datetime
from virustotal_func import VirusTotalFunc

from pprint import pprint

class EmailAnalyzer:
	def analyze_attachment(file_to_analyze):
		try:
			response = VirusTotalFunc.get_file_info(file_to_analyze)
			malicious = response['attributes']['last_analysis_stats']['malicious']
			undetected = response['attributes']['last_analysis_stats']['undetected']
			total = malicious + undetected
			print("\tVT Detections: %d/%d" % (malicious, total))
		except Exception as e:
			print("\tVT: File hash not found in VirusTotal")


	def analyze_url(url_to_analyze):
		try:
			response = VirusTotalFunc.scan_url(url_to_analyze)
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

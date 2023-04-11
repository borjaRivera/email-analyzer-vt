import base64
from contextlib import suppress
import datetime
from utils.virustotal_func import VirusTotalFunc


class EmailContentAnalyzer:

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
			
			try:
				last_analysis_date = datetime.datetime.fromtimestamp(response['attributes']['last_analysis_date'])
				print("\t\t\t[*] Last analysis date: ", last_analysis_date)
			except:
				pass

			try:
				last_modification_date = datetime.datetime.fromtimestamp(response['attributes']['last_modification_date'])
				print("\t\t\t[*] Last modification date: ", last_modification_date)
			except:
				pass
			
			try:
				first_submission_date = datetime.datetime.fromtimestamp(response['attributes']['first_submission_date'])
				print("\t\t\t[*] First submission date: ", first_submission_date)
			except: 
				pass


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
		
		try:
			last_analysis_date = datetime.datetime.fromtimestamp(response['attributes']['last_analysis_date'])
			print("\t\t\t[*] Last analysis date: ", last_analysis_date)
		except:
			pass

		try:
			last_modification_date = datetime.datetime.fromtimestamp(response['attributes']['last_modification_date'])
			print("\t\t\t[*] Last modification date: ", last_modification_date)
		except:
			pass
		
		try:
			continent =  response['attributes']['continent'] 
			country = response['attributes']['country']
			print("\t\t\t[*] Continent: ", continent)
			print("\t\t\t[*] Country: ", country)
		except:
			pass

		try:
			as_owner = response['attributes']['as_owner'] 
			print("\t\t\t[*] AS owner: ", as_owner)
		except:
			as_owner = "UNKNOWN"
			print("\t\t\t[*] AS owner: ", as_owner)



	def analyze_attachment(hash_to_analyze):
		try:
			response = VirusTotalFunc.get_file_info(hash_to_analyze)

			EmailContentAnalyzer.get_basic_analysis(response)

			full_report_url = "https://www.virustotal.com/gui/file/" + hash_to_analyze + "\n"

			print("\t\t\t[*] Full report: ", full_report_url)

		except Exception as e:
			print("\t\t\tNot found in VirusTotal", e)


	def analyze_url(url_to_analyze):
		try:
			response = VirusTotalFunc.scan_url(url_to_analyze)

			EmailContentAnalyzer.get_basic_analysis(response)

			url_id = base64.urlsafe_b64encode(url_to_analyze.encode()).decode().strip("=")

			full_report_url = "https://www.virustotal.com/gui/url/" + url_id

			print("\t\t\t[*] Full report: ", full_report_url)

		except Exception as e:
			print("\t\t\tNot found in VirusTotal", e)


	def analyze_ip(ip_to_analyze):
		try:
			response = VirusTotalFunc.scan_ip(ip_to_analyze)

			EmailContentAnalyzer.get_basic_analysis_ip(response)

			full_report_url = "https://www.virustotal.com/gui/ip-address/" + ip_to_analyze

			print("\t\t\t[*] Full report: ", full_report_url)

		except Exception as e:
			print("\t\t\tNot found in VirusTotal", e)
import hashlib
import re


class EmailExtractor:


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
        return EmailExtractor.unique(ip_addresses)


    def recursive(payload):
        for i in payload:
            if i.get_content_maintype() == "multipart":
                mail = i.get_payload()
                body = EmailExtractor.recursive(mail)
                return body
            elif i.get_content_maintype()  == "text":
                return i.get_payload()


    def get_body(email_message):
        maintype = email_message.get_content_maintype()
        payload = email_message.get_payload()
        if maintype == "multipart":
            body = EmailExtractor.recursive(payload)
        elif maintype == "text":
            body = email_message.get_payload()
        return body


    def get_links(email_message):
        #print(body)
        links = []
        regex = re.compile(r'http.+\.[0-9a-zA-Z\-\_\/\%\&\|\\\+\=\?\(\)\$\!]+\.[0-9a-zA-Z\-\_\/\%\&\|\\\+\=\?\(\)\$\!\:\#]+')
        linksaux = regex.findall(str(email_message))
        for link in linksaux:
            if link.find(' ') == -1 and link.find('\t') == -1:
                links.append(link)

        return EmailExtractor.unique(links)


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

                    hashmd5 = hashlib.md5(attachment["file"]).hexdigest()
                    attachment['hashmd5'] = hashmd5
                    #print("md5: ", attachment['hashmd5']  )

                    sha1 = hashlib.sha1(attachment["file"]).hexdigest()
                    attachment['sha1'] = sha1
                    #print("sha1: ", attachment['sha1']  )

                    sha256 = hashlib.sha256(attachment["file"]).hexdigest()
                    attachment['sha256'] = sha256
                    #print("sha256: ", attachment['sha256']  )

                    
                    attachments.append(attachment)

            except:
                pass
                #print("File hash not found in VirusTotal")
        return attachments



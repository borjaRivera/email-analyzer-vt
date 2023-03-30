from email import generator
import imaplib
import email
import yaml
import os

contador = 0

def saveEmailToFile(msg, outfile_name):
    path = "/home/kali/Documents/TFM/virustotal-python/incident_handling/emails"
    outfile= os.path.join(path, outfile_name)
    with open(outfile, 'w') as out:
        gen = generator.Generator(out)
        gen.flatten(msg)



with open("credentials.yml") as f:
    content = f.read()
    
# from credentials.yml import user name and password
my_credentials = yaml.load(content, Loader=yaml.FullLoader)

#Load the user name and passwd from yaml file
user, password = my_credentials["user"], my_credentials["password"]

#URL for IMAP connection
imap_url = 'imap.gmail.com'

# Connection with GMAIL using SSL
my_mail = imaplib.IMAP4_SSL(imap_url)

# Log in using your credentials
my_mail.login(user, password)

# Select the Inbox to fetch messages
my_mail.select('Inbox')

#Define Key and Value for email search
#For other keys (criteria): https://gist.github.com/martinrusev/6121028#file-imap-search
key = 'FROM'
value = 'lb939300.cantabria@colaboradorbymovil.com'
_, data = my_mail.search(None, key, value)  #Search for emails with specific key and value

mail_id_list = data[0].split()  #IDs of all emails that we want to fetch 

msgs = [] # empty list to capture all messages
#Iterate through messages and extract data into the msgs list
for num in mail_id_list:
    typ, data = my_mail.fetch(num, '(RFC822)') #RFC822 returns whole message (BODY fetches just body)
    msgs.append(data)

#Now we have all messages, but with a lot of details
#Let us extract the right text and print on the screen

#In a multipart e-mail, email.message.Message.get_payload() returns a 
# list with one item for each part. The easiest way is to walk the message 
# and get the payload on each part:
# https://stackoverflow.com/questions/1463074/how-can-i-get-an-email-messages-text-content-using-python

# NOTE that a Message object consists of headers and payloads.



for msg in msgs[::-1]:
    for response_part in msg:
        if type(response_part) is tuple:
            my_msg=email.message_from_bytes((response_part[1]))

            print("_________________________________________")
            print(my_msg)
            contador = contador + 1 
            name = "email_" + str(contador) + ".eml"
            saveEmailToFile(my_msg, name)

            """
            print ("SUBJECT:", my_msg['subject'])
            print ("FROM:", my_msg['from'])
            print ("TO:", my_msg['to'])
            print ("BODY:")
            for part in my_msg.walk():  
                #print(part.get_content_type())
                if part.get_content_type() == 'text/plain':
                    print (part.get_payload())
            """
from email import generator
import imaplib
import email
import yaml
import os

class GmailExtractor:


    def get_credentials():
        with open("credentials.yml") as f:
            content = f.read()
            
        # from credentials.yml import user name and password
        my_credentials = yaml.load(content, Loader=yaml.FullLoader)

        #Load the user name and passwd from yaml file
        user, password = my_credentials["user"], my_credentials["password"]

        return user,password

    def connect():
        #URL for IMAP connection
        imap_url = 'imap.gmail.com'

        # Connection with GMAIL using SSL
        my_mail_connection = imaplib.IMAP4_SSL(imap_url)

        return my_mail_connection

    def login(mail_connection):
        
        credentials = GmailExtractor.get_credentials()
        # Log in using your credentials
        mail_connection.login(credentials[0], credentials[1])

    def save_email_to_file(msg, outfile_name):
        path = os.getcwd() + "/tmp"

        if not os.path.exists(path): 
            os.makedirs(path)

            
        outfile = os.path.join(path, outfile_name)
        with open(outfile, 'w') as out:
            gen = generator.Generator(out)
            gen.flatten(msg)


    def search_all(my_mail, key):
        # Select the Inbox to fetch messages
        my_mail.select('Inbox')

        #Define Key and Value for email search
        #For other keys (criteria): https://gist.github.com/martinrusev/6121028#file-imap-search
        _, data = my_mail.search(None, key)  #Search for emails with specific key and value

        mail_id_list = data[0].split()  #IDs of all emails that we want to fetch 

        msgs = [] # empty list to capture all messages

        #Iterate through messages and extract data into the msgs list
        for num in mail_id_list:
            typ, data = my_mail.fetch(num, '(RFC822)') #RFC822 returns whole message (BODY fetches just body)
            msgs.append(data)

        return msgs
    
    def search_all_emails_by_sender(my_mail, key, value):
        # Select the Inbox to fetch messages
        my_mail.select('Inbox')

        _, data = my_mail.search(None, key, value)  #Search for emails with specific key and value

        mail_id_list = data[0].split()  #IDs of all emails that we want to fetch 

        msgs = [] # empty list to capture all messages

        #Iterate through messages and extract data into the msgs list
        for num in mail_id_list:
            typ, data = my_mail.fetch(num, '(RFC822)') #RFC822 returns whole message (BODY fetches just body)
            msgs.append(data)

        return msgs


    def extract(key, value):
        contador = 0

        try:
            my_mail_connection = GmailExtractor.connect()
        except Exception as e:
            print("Failed connecting to email", e)

        try:
            GmailExtractor.login(my_mail_connection)
        except Exception as e:
            print("Failed login to email account", e)

        #Define Key and Value for email search
        #For other keys (criteria): https://gist.github.com/martinrusev/6121028#file-imap-search

        if key == "ALL":
            msgs = GmailExtractor.search_all(my_mail_connection, "ALL")

        elif key == "FROM":
            msgs = GmailExtractor.search_all_emails_by_sender(my_mail_connection, "FROM", value)

        for msg in msgs[::-1]:
            for response_part in msg:
                if type(response_part) is tuple:
                    my_msg=email.message_from_bytes((response_part[1]))

                    contador = contador + 1 
                    name = "email_" + str(contador) + ".eml"
                    GmailExtractor.save_email_to_file(my_msg, name)


""""
def main():
    contador = 0

    my_mail_connection = GmailExtractor.connect()

    GmailExtractor.login(my_mail_connection)

    #Define Key and Value for email search
    #For other keys (criteria): https://gist.github.com/martinrusev/6121028#file-imap-search
    # msgs = GmailExtractor.search_all_emails_by_sender(my_mail_connection, "FROM", "lb939300.cantabria@colaboradorbymovil.com")
    msgs = GmailExtractor.search_all(my_mail_connection, "ALL")


    for msg in msgs[::-1]:
        for response_part in msg:
            if type(response_part) is tuple:
                my_msg=email.message_from_bytes((response_part[1]))

                #print("_________________________________________")
                #print(my_msg)
                contador = contador + 1 
                name = "email_" + str(contador) + ".eml"
                GmailExtractor.save_email_to_file(my_msg, name)

if __name__ == '__main__':
	main()

"""
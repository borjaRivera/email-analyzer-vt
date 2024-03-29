# email-analyzer-vt :email:

A Python tool to analyze suspicious phishing emails of a Gmail account inbox.


## Installation 🛠

```bash
sudo apt-get updade
sudo apt-get install python3

git clone https://github.com/borjaRivera/email-analyzer-vt.git

pip install PyYAML
pip install virustotal-python
```




## Getting Started
Configure config.yml adding the Gmail address to be analyzed, Application Password and your Virustotal API Key.

### Get a VirusTotal API Key 🔑
[Sign up](https://www.virustotal.com/gui/join-us) for a VirusTotal account. Then, view your VirusTotal API key.

### How to get an Application Password from Gmail account
In that Gmail account that you want to scan, you must enable two-step verification and activate an Application Password. This link [https://support.google.com/accounts/answer/185833?hl=es] explains how to do this. A 16-character password will be generated, which you will have to enter in the config.yml file.

### Modify config.yml with email credentials and VT API Key
Create the file config.yml in the root directory and introduce the email address to analyze, the Application Password created and the VirusTotal API Key.

![Configuration](./lib/images/config.png)


## Usage

```bash

usage: main.py [-h] [-a] [-e filename] [-s address]

options:
-h, --help            show this help message and exit
-a, --all             get all files from e-mail inbox account and analyze them.
-e filename, --email filename
                      analyze a specific .eml file.
-s address, --sender address
                      analyze all e-mails from a specific address sender.

```

## Authors & Contributors

* [**borjaRivera**](https://github.com/borjaRivera) - *Author*


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) for details.

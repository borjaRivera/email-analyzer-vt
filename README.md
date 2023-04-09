# email-analyzer-vt :email:

A Python tool to analyze suspicious phising emails of an e-mail account inbox.


## Installation 🛠

```bash
sudo apt-get updade
sudo apt-get install python3

git clone https://github.com/borjaRivera/email-analyzer-vt.git

## Get a VirusTotal API Key 🔑

[Sign up](https://www.virustotal.com/gui/join-us) for a VirusTotal account. Then, view your VirusTotal API key.

```

## Code Snippets

> Further usage examples can be found in [examples](examples).

### Send a file for analysis 🔎

```python
import virustotal_python
import os.path
from pprint import pprint

FILE_PATH = "/path/to/file/to/scan.txt"

# Create dictionary containing the file to send for multipart encoding upload
files = {"file": (os.path.basename(FILE_PATH), open(os.path.abspath(FILE_PATH), "rb"))}

with virustotal_python.Virustotal("<VirusTotal API Key>") as vtotal:
    resp = vtotal.request("files", files=files, method="POST")
    pprint(resp.json())
```

### Get information about a file 📁

```python
import virustotal_python
from pprint import pprint

# The ID (either SHA-256, SHA-1 or MD5 hash) identifying the file
FILE_ID = "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115"

with virustotal_python.Virustotal("<VirusTotal API Key>") as vtotal:
    resp = vtotal.request(f"files/{FILE_ID}")
    pprint(resp.data)
```

### Send a URL 🔗 for analysis and get the report 📄

```python
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode

url = "ihaveaproblem.info"

with virustotal_python.Virustotal("<VirusTotal API Key>") as vtotal:
    try:
        resp = vtotal.request("urls", data={"url": url}, method="POST")
        # Safe encode URL in base64 format
        # https://developers.virustotal.com/reference/url
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        report = vtotal.request(f"urls/{url_id}")
        pprint(report.object_type)
        pprint(report.data)
    except virustotal_python.VirustotalError as err:
        print(f"Failed to send URL: {url} for analysis and get the report: {err}")
```

### Get information about a domain:

```python
import virustotal_python
from pprint import pprint

domain = "virustotal.com"

with virustotal_python.Virustotal("<VirusTotal API Key>") as vtotal:
    resp = vtotal.request(f"domains/{domain}")
    pprint(resp.data)
```

## Development

[Black](https://github.com/psf/black) is used for code formatting.

### Unit Tests

Install the development dependencies using Poetry:

```bash
poetry install && poetry shell
```

To run the unit tests, run `pytest` from the root of the project:

```bash
pytest --cov=virustotal_python
```

### Publishing a new release

```bash
# Run from the master branch
export VERSION=x.x.x
git commit --allow-empty -m "Publish $VERSION"
git tag -a $VERSION -m "Version $VERSION"
git push --tags
```

## Authors & Contributors

* [**dbrennand**](https://github.com/dbrennand) - *Author*

* [**smk762**](https://github.com/smk762) - *Contributor*

## Changelog

See the [CHANGELOG](CHANGELOG.md) for details.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) for details.

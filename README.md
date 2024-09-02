# Google Audit

This is a handy webscraper for auditing Google Workspaces against CIS benchmarks.

The tool spawns a Chromium browser and navigates automatically, grabbing and parsing the relevant data.

After the data is grabbed, the analysis portion begins. The tool will display the expected value and the found value, and the user enters y or n depending on whether the criteria is met. Many results are automatically validated, but some require human interpretation.

After the analysis is complete, the raw results are logged in results.csv.

## Install

```bash
# Clone down repo and cd in
python3 -m venv venv
source venv/bin/activate
which pip  # Verify pip is in venv directory
pip install -r requirements.txt
```


## Usage
```bash
source venv/bin/activate
python3 GoogleAudit.py
```

Authors:
- Alex Wyner - https://github.com/awyner

- Chris Melnyk - https://github.com/wagyus

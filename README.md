# netAudit

networkAudit is a simple tool that shows what devices are connected to your local network.

It can show:

* Computers, phones, printers, cameras, IPs, names of devices and changes to devices that are new or missing.

Think of it like running an audit for the network that you're authorized to run it on.

## What You Need

NetAudit uses Python.

Python is a free program that lets your computer run tools like netAudit.

1. Download and install Python from python.org
2. During installation, select **“Add Python to PATH”**
3. Download the NetAudit files
4. Open the folder containing `netaudit.py`
5. Click the folder address bar, type:

```text
cmd
```
and press **Enter**.
A black Command Prompt window will open in that folder.
## Run Your First Scan

Type:

```bash
python netaudit.py 192.168.1.0/24 --baseline baseline.json
```

Then press **Enter**.

This means:

* `python` = run the program using Python
* `netaudit.py` = start NetAudit
* `192.168.1.0/24` = scan your local network
* `--baseline baseline.json` = save this scan so NetAudit can compare it later

## Check for Changes Later

Run the same command again:

```bash
python netaudit.py 192.168.1.0/24 --baseline baseline.json
```

NetAudit will tell you if a device is:

```text
[NEW]      A new device appeared
[MISSING]  A device disappeared
[CHANGED]  Device information changed
[PORTS]    A network service changed
```

## Save the

If the changes are expected run your new starting point.

```bash
python netaudit.py 192.168.1.0/24 --baseline baseline.json --update-baseline
```

## Create your report.

NetAudit can create:

* **HTML** easiest to read in a web browser
* **CSV** opens in Excel

That is the basic idea:


**1.Install Python 
2.open Command Prompt
3.run NetAudit
4.check what changed.**

**Only** scan networks you own or have permission to scan.

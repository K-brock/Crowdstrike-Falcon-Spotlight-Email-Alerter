# **CrowdStrike Falcon Spotlight Email Sender** 🛡️
> ⚠️ This tool is personally developed and is not supported, maintained, or endorsed by CrowdStrike. 

*Using Falcon Spotlight with a manual patching process? How much time are you spending reaching out to users informing them which software they need to update?*

*Streamline your workflow through automation! Leveraging the CrowdStrike Falcon Spotlight API, automatically identify the most critical vulnerabilities on each user's device, delivering personalized email notifications with tailored guidance on updating their applications.*

![Screenshot 2025-03-22 233111](https://github.com/user-attachments/assets/18cbca6d-22c4-46fd-aded-e30e9d92d2b7)

---

## **Features** 📋

- **Device Discovery**: Automatically discovers and tracks all devices in your CrowdStrike environment
- **Device Owner Mapping**: Maintains a mapping between device IDs, hostnames, and owner email addresses 
- **Vulnerability Prioritization**: Focuses on most at risk applications with available remediations  
- **Deduplication**: Consolidates multiple vulnerabilities for the same application  
- **Email Notifications**: Sends professionally formatted HTML emails via Outlook  
- **Customizable**: Easily adjust vulnerability filters, email content, and more  

---

## **Prerequisites** ✅

- Python 3.6+  
- CrowdStrike Falcon API credentials
- API Scopes [spotlight-vulnerabilities:read] [hosts:read]
- Microsoft Outlook installed locally
- Windows OS

Emails are dispatched locally through the COM API - as such there is no need for a Graph API / Entra custom App integration. Emails will be sent from the locally logged in user account, as such the reccomendation is to deploy to a VM and create a new mailbox 'vulnerabilityNotifier@domain'. 

---

## **Required Python Packages** 📦

- `falconpy`  
- `python-dotenv`  
- `pywin32`  
- `pathlib`  

---

## **Installation** 🧰

**Clone this repository:**
```bash
git clone https://github.com/K-brock/Crowdstrike-Falcon-Spotlight-Email-Alerter
```

**Install required packages:**
```bash
pip install -r requirements.txt
```

**Create a `.env` file in the project directory with your CrowdStrike API credentials:**
```dotenv
API_KEY='your_crowdstrike_client_id'
API_SECRET='your_crowdstrike_client_secret'
FALCON_CLOUD='us-2'  # Change to your appropriate region (us-1, us-2, eu-1, etc.)
```

---

## **Usage** 🚀

### **Initial Setup**

Run the script once to generate the device mapping CSV:
```bash
python Spotlight_Sender.py
```

Open `device_mappings.csv` and add email addresses for each device owner.
Devices with empty addresses will be ignored (explicit inclusion)

### **Regular Operation**

Once email addresses are populated, simply run the script:
```bash
python Spotlight_Sender.py
```

The script will:

- Update the device list with any new devices  
- Scan for vulnerabilities on each device  
- Send email notifications to owners of devices with vulnerabilities  

---

## **Scheduling** ⏰

For automated operation, consider setting up a scheduled task (Windows) to run the script at regular intervals.

---

## **Customization** 🛠️

### **Vulnerability Filtering**

Edit the `base_filter_components` dictionary in the `get_vulnerabilities_for_aid` method to adjust which vulnerabilities are included. For example, to only include actively exploited vulnerabilities:

```python
base_filter_components = {
    "AID": f"aid:'{aid}'",
    "OpenV": "status:!'closed'",
    "Remediation_Possible": "cve.remediation_level:'O'",
    "Actively_Exploited": "cve.exploitability_status:'true'"
    # Actively exploited.. "XploitS": "cve.exploit_status:['60','90']",
}
```

### **Email Content**

Modify the `generate_email_content` method to change the email format, content, or styling.

### **Logging**

The script logs all activity to `RuntimeLogs.log` in the script directory. Check this file for troubleshooting or to monitor script execution. It is very high fidelity and should answer all your questions. Logs are written over each execution.

---

## **License** 📄

MIT License

---

## **Acknowledgments** 🙏

This tool uses the [FalconPy SDK](https://github.com/CrowdStrike/falconpy) provided by CrowdStrike.

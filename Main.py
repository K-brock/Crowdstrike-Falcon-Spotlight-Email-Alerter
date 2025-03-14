from falconpy import SpotlightVulnerabilities, Hosts
from datetime import datetime
from collections import defaultdict
from pathlib import Path
from dotenv import load_dotenv
import csv
import os
import time
import logging
import win32com.client as win32

# Set up Logging
logger = logging.getLogger("vulnerability_notifier")
logger.setLevel(logging.DEBUG)  # Capture all levels
file_handler = logging.FileHandler("RuntimeLogs.log", mode="w")
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


class VulnerabilityNotifier:
    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv("API_KEY")
        self.api_secret = os.getenv("API_SECRET")
        self.falcon_cloud = os.getenv('FALCON_CLOUD', 'us-2')
        
        if not all([self.api_key, self.api_secret]):
            logger.error("API_KEY and API_SECRET must be set in environment variables")
            raise EnvironmentError("API_KEY and API_SECRET must be set in environment variables")
        
        self.falcon_vuln = SpotlightVulnerabilities(
            client_id=self.api_key,
            client_secret=self.api_secret
        )
        
        self.csv_path = Path(__file__).parent / 'device_mappings.csv'
        logger.debug("VulnerabilityNotifier initialized.")

    def create_csv_if_not_exists(self):
        """Initialize CSV file if it doesn't exist"""
        if not self.csv_path.exists():
            with open(self.csv_path, 'w', newline='', encoding='utf-8') as file:
                writer = csv.DictWriter(file, fieldnames=['AID', 'hostname', 'email address'])
                writer.writeheader()
            logger.info(f"Created new CSV file: {self.csv_path}")

    def get_devices(self):
        """Fetch devices from CrowdStrike API"""
        falcon_hosts = Hosts(
            client_id=self.api_key,
            client_secret=self.api_secret,
            base_url=f"https://api.{self.falcon_cloud}.crowdstrike.com"
        )
        
        devices = []
        offset = None
        
        try:
            while True:
                response = falcon_hosts.query_devices_by_filter_scroll(
                    offset=offset,
                    limit=5000,
                    sort="hostname.asc"
                )
                
                if response["status_code"] != 200:
                    logger.error(f"Error querying devices: {response['body']}")
                    break
                    
                if response['body']['resources']:
                    details = falcon_hosts.get_device_details(ids=response['body']['resources'])
                    
                    if details["status_code"] == 200:
                        for device in details['body']['resources']:
                            if device.get('device_id') and device.get('hostname'):
                                devices.append({
                                    'aid': device['device_id'],
                                    'hostname': device['hostname'].upper()
                                })
                
                offset = response['body'].get('offset')
                if not offset:
                    break
                    
        except Exception as e:
            logger.error(f"Error fetching devices: {str(e)}")
            
        logger.debug(f"Fetched {len(devices)} devices.")
        return devices

    def update_device_mappings(self):
        """Update device mappings in CSV"""
        devices = self.get_devices()
        if not devices:
            logger.warning("No devices found or error occurred during device fetch")
            return

        try:
            existing_data = self.read_existing_mappings()
            new_entries = 0
            updated_entries = 0
            
            for device in devices:
                aid = device['aid']
                if aid not in existing_data:
                    existing_data[aid] = {
                        'hostname': device['hostname'],
                        'email address': ''
                    }
                    new_entries += 1
                elif existing_data[aid]['hostname'] != device['hostname']:
                    logger.info(f"Hostname changed for AID {aid}: "
                                f"{existing_data[aid]['hostname']} -> {device['hostname']}")
                    existing_data[aid]['hostname'] = device['hostname']
                    updated_entries += 1

            self.write_mappings_to_csv(existing_data)
            logger.info(f"CSV Update Complete - New: {new_entries}, Updated: {updated_entries}")

        except Exception as e:
            logger.error(f"Error updating device mappings: {str(e)}")

    def read_existing_mappings(self):
        """Read existing mappings from CSV"""
        existing_data = {}
        try:
            with open(self.csv_path, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    if row['AID'].strip():
                        existing_data[row['AID']] = {
                            'hostname': row['hostname'],
                            'email address': row['email address']
                        }
        except FileNotFoundError:
            logger.warning("No existing mappings file found")
        except Exception as e:
            logger.error(f"Error reading existing mappings: {str(e)}")
        return existing_data

    def write_mappings_to_csv(self, data):
        """Write mappings to CSV file"""
        try:
            with open(self.csv_path, 'w', newline='', encoding='utf-8') as file:
                writer = csv.DictWriter(file, fieldnames=['AID', 'hostname', 'email address'])
                writer.writeheader()
                
                sorted_data = sorted(
                    ((aid, details) for aid, details in data.items() if aid.strip()),
                    key=lambda x: x[1]['hostname']
                )
                
                for aid, details in sorted_data:
                    writer.writerow({
                        'AID': aid,
                        'hostname': details['hostname'],
                        'email address': details['email address']
                    })
            logger.debug("Device mappings successfully written to CSV.")
        except Exception as e:
            logger.error(f"Error writing mappings to CSV: {str(e)}")

    def get_vulnerabilities_for_aid(self, aid):
        """Get vulnerabilities for a specific AID"""
        filter_components = {
            "AID": f"aid:'{aid}'",
            "ExPRT": "cve.exprt_rating:['HIGH','CRITICAL']",
            "XploitS": "cve.exploit_status:['60','90']",
            "OpenV": "status:!'closed'",
            "Remediation_Possible": "cve.remediation_level:'O'"
        }
        
        filter_string = "+".join(filter_components.values())
        
        try:
            response = self.falcon_vuln.query_vulnerabilities(filter=filter_string)
            if response["status_code"] != 200:
                logger.error(f"Error querying vulnerabilities for AID {aid}: {response['status_code']}")
                return None
                
            logger.debug(f"Vulnerabilities queried for AID {aid}: {response['body'].get('resources')}")
            return response["body"]["resources"]
        except Exception as e:
            logger.error(f"Error querying vulnerabilities for AID {aid}: {str(e)}")
            return None

    def process_vulnerabilities(self, vuln_ids):
        """Process vulnerability details and return deduplicated results"""
        dedup_vulns = defaultdict(lambda: {'cves': set(), 'severity': '', 'expert_rating': '', 'action': ''})
        severity_order = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
        
        batch_size = 10
        for i in range(0, len(vuln_ids), batch_size):
            batch = vuln_ids[i:i+batch_size]
            
            try:
                vuln_details = self.falcon_vuln.get_vulnerabilities(ids=batch)
                
                if vuln_details["status_code"] == 200:
                    for vuln in vuln_details["body"]["resources"]:
                        product_name = vuln.get('apps', [{}])[0].get('product_name_version', 'N/A')
                        action = vuln.get('remediation', {}).get('entities', [{}])[0].get('action', 'N/A')
                        
                        if product_name == 'N/A':
                            continue
                            
                        dedup_key = product_name
                        
                        if 'cve' in vuln:
                            dedup_vulns[dedup_key]['cves'].add(vuln['cve'].get('id', 'N/A'))
                            
                            if not dedup_vulns[dedup_key]['action'] and action != 'N/A':
                                dedup_vulns[dedup_key]['action'] = action
                            
                            current_severity = vuln['cve'].get('severity', '')
                            current_rating = vuln['cve'].get('exprt_rating', '')
                            
                            if severity_order.get(current_severity, -1) > severity_order.get(dedup_vulns[dedup_key]['severity'], -1):
                                dedup_vulns[dedup_key]['severity'] = current_severity
                            
                            if severity_order.get(current_rating, -1) > severity_order.get(dedup_vulns[dedup_key]['expert_rating'], -1):
                                dedup_vulns[dedup_key]['expert_rating'] = current_rating
                
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Error processing vulnerability batch: {str(e)}")
                continue
                
        logger.debug("Vulnerability processing complete.")
        return dedup_vulns

    def generate_email_content(self, dedup_vulns):
        """
        Generate HTML content for the email notification with CrowdStrike theming
        
        Args:
            dedup_vulns: Dictionary of vulnerabilities
        
        Returns:
            str: HTML content for the email
        """
        # Define severity colors
        severity_colors = {
            'CRITICAL': '#e30000',  # Red
            'HIGH': '#f97316',      # Orange
            'MEDIUM': '#f59e0b',    # Amber
            'LOW': '#64748b'        # Slate
        }
        
        # Start building the HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Software Update Alert</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, Helvetica, sans-serif; background-color: #f5f5f5; color: #333333;">
            <!-- Main Table -->
            <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f5f5f5;">
                <tr>
                    <td align="center" style="padding: 20px 0;">
                        <!-- Email Container -->
                        <table width="600" cellpadding="0" cellspacing="0" border="0" style="background-color: #ffffff; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
                            <!-- Header -->
                            <tr>
                                <td style="background-color: #e30000; padding: 20px; text-align: center; border-radius: 5px 5px 0 0;">
                                    <h1 style="color: #ffffff; margin: 0; font-size: 24px;">Software Update Alert</h1>
                                </td>
                            </tr>
                            
                            <!-- Content -->
                            <tr>
                                <td style="padding: 20px;">
                                    <!-- Introduction -->
                                    <p style="text-align: center;">Vulnerable software has been identified as running on your device.</p>
                                    <p style="text-align: center;">Please assist the security team by updating the following applications at your earliest convenience:</p>
        """
        
        # Add vulnerability cards
        for i, (product, data) in enumerate(sorted(dedup_vulns.items()), 1):
            if i > 5:  # Limit to top 5 vulnerabilities
                break
            
            severity = data['expert_rating'] or 'MEDIUM'
            color = severity_colors.get(severity, '#64748b')
            
            html_content += f"""
                                    <!-- Vulnerability {i} -->
                                    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom: 15px; background-color: #f9fafb; border-radius: 5px; border-left: 5px solid {color};">
                                        <tr>
                                            <td style="padding: 15px;">
                                                <p style="margin-top: 0; margin-bottom: 5px; font-weight: bold; font-size: 16px;">
                                                    {product}
                                                    <span style="display: inline-block; background-color: {color}; color: white; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; margin-left: 10px;">{severity}</span>
                                                </p>
                                                <p style="margin-top: 8px; margin-bottom: 0; font-size: 14px;">{data['action']}</p>
                                            </td>
                                        </tr>
                                    </table>
            """
        
        # Add footer and close tags
        html_content += """
                                    <p style="margin-top: 20px; text-align: center;">If you need assistance, please contact IT.</p>
                                </td>
                            </tr>
                            
                            <!-- Footer -->
                            <tr>
                                <td style="background-color: #222222; padding: 15px; text-align: center; color: #ffffff; font-size: 14px; border-radius: 0 0 5px 5px;">
                                    <p style="margin: 0;">&copy; The Security Team</p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        
        logger.debug("Email content generated.")
        return html_content

    def Email_via_outlook(self, to_address, subject, body):
        """
        Send an HTML email using Outlook COM API
        
        Args:
            to_address: Email recipient
            subject: Email subject
            body: HTML content for the email
        """
        try:
            logger.info("Attempting to send HTML email via Outlook COM.")
            logger.debug(f"Recipient: {to_address}")
            
            # Create Outlook object
            logger.debug("Dispatching Outlook Application...")
            outlook = win32.Dispatch('Outlook.Application')
            logger.debug("Outlook Application object created successfully.")
            
            # Create a new mail item (0 = olMailItem)
            logger.debug("Creating a new mail item...")
            mail = outlook.CreateItem(0)
            
            # Set up HTML email format
            mail.To = to_address
            mail.Subject = subject
            mail.HTMLBody = body
            
            logger.debug("Mail fields set. Attempting to send mail...")
            mail.Send()
            logger.info(f"Mail.Send() executed successfully for recipient {to_address}.")
            
        except Exception as e:
            logger.exception("Error sending email via Outlook COM API.")

    def process_all_devices(self):
        """Process all devices with complete mapping information"""
        try:
            with open(self.csv_path, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    if all(row[field].strip() for field in ['AID', 'hostname', 'email address']):
                        aid = row['AID']
                        hostname = row['hostname']
                        email = row['email address']
                        
                        logger.info(f"Processing device: {hostname} ({aid})")
                        
                        # Get vulnerabilities
                        vuln_ids = self.get_vulnerabilities_for_aid(aid)
                        if not vuln_ids:
                            logger.info(f"No vulnerabilities found for {hostname}")
                            continue
                            
                        # Process vulnerabilities
                        dedup_vulns = self.process_vulnerabilities(vuln_ids)
                        
                        if dedup_vulns:
                            # Generate email content and send via Outlook
                            email_content = self.generate_email_content(dedup_vulns)
                            self.Email_via_outlook(
                                to_address=email,
                                subject="Action Required: Update Your Software",
                                body=email_content
                            )
                        else:
                            logger.info(f"No actionable vulnerabilities found for {hostname}")
                            
                        time.sleep(1)  # Rate limiting between devices
                    else:
                        # Extract hostname if present; default to "UNKNOWN" if not.
                        missingHostname = row.get('hostname', 'UNKNOWN')
                        logger.info(f"No email address assigned to host {missingHostname} in device_mappings.csv. Please populate document if expected")
                        
        except Exception as e:
            logger.error(f"Error processing devices: {str(e)}")


def main():
    try:
        notifier = VulnerabilityNotifier()
        
        # Update device mappings first
        logger.info("Updating device mappings...")
        notifier.create_csv_if_not_exists()
        notifier.update_device_mappings()
        
        # Then process vulnerabilities for all devices
        logger.info("Processing vulnerabilities for all devices...")
        notifier.process_all_devices()
        
    except Exception as e:
        logger.error(f"Fatal error in main execution: {str(e)}")


if __name__ == "__main__":
    main()

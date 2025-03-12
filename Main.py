from falconpy import SpotlightVulnerabilities, Hosts
from datetime import datetime
from collections import defaultdict
from pathlib import Path
from dotenv import load_dotenv
import csv
import os
import time
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnerability_notifications.log'),
        logging.StreamHandler()
    ]
)

class VulnerabilityNotifier:
    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv("API_KEY")
        self.api_secret = os.getenv("API_SECRET")
        self.falcon_cloud = os.getenv('FALCON_CLOUD', 'us-2')
        
        if not all([self.api_key, self.api_secret]):
            raise EnvironmentError("API_KEY and API_SECRET must be set in environment variables")
        
        self.falcon_vuln = SpotlightVulnerabilities(
            client_id=self.api_key,
            client_secret=self.api_secret
        )
        
        self.csv_path = Path(__file__).parent / 'device_mappings.csv'

    def create_csv_if_not_exists(self):
        """Initialize CSV file if it doesn't exist"""
        if not self.csv_path.exists():
            with open(self.csv_path, 'w', newline='', encoding='utf-8') as file:
                writer = csv.DictWriter(file, fieldnames=['AID', 'hostname', 'email address'])
                writer.writeheader()
            logging.info(f"Created new CSV file: {self.csv_path}")

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
                    logging.error(f"Error querying devices: {response['body']}")
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
            logging.error(f"Error fetching devices: {str(e)}")
            
        return devices

    def update_device_mappings(self):
        """Update device mappings in CSV"""
        devices = self.get_devices()
        if not devices:
            logging.warning("No devices found or error occurred during device fetch")
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
                    logging.info(f"Hostname changed for AID {aid}: "
                          f"{existing_data[aid]['hostname']} -> {device['hostname']}")
                    existing_data[aid]['hostname'] = device['hostname']
                    updated_entries += 1

            self.write_mappings_to_csv(existing_data)
            logging.info(f"CSV Update Complete - New: {new_entries}, Updated: {updated_entries}")

        except Exception as e:
            logging.error(f"Error updating device mappings: {str(e)}")

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
            logging.warning("No existing mappings file found")
        return existing_data

    def write_mappings_to_csv(self, data):
        """Write mappings to CSV file"""
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
                logging.error(f"Error querying vulnerabilities for AID {aid}: {response['status_code']}")
                return None
                
            return response["body"]["resources"]
        except Exception as e:
            logging.error(f"Error querying vulnerabilities for AID {aid}: {str(e)}")
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
                logging.error(f"Error processing vulnerability batch: {str(e)}")
                continue
                
        return dedup_vulns

    def generate_email_content(self, hostname, dedup_vulns):
        """Generate email content for vulnerabilities"""
        email_content = []
        email_content.append(f"Subject: Security Update Required - {hostname}\n")
        email_content.append("Hello,\n")
        email_content.append("This is an automated security notification.\n")
        email_content.append("We have identified vulnerable software running on your device that requires immediate attention. "
                           "Please assist the security team by updating the following applications to their latest versions:\n")
        
        for i, (product, data) in enumerate(sorted(dedup_vulns.items()), 1):
            if i > 5:  # Limit to top 5 vulnerabilities
                break
            email_content.append(f"{i}. Application: {product}")
            email_content.append(f"   Action Required: {data['action']}")
            email_content.append(f"   Urgency: {data['expert_rating']}\n")
        
        email_content.append("\nIf you need assistance, please contact IT.")
        email_content.append("\nBest Regards,")
        email_content.append("Security Team")
        
        return "\n".join(email_content)

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
                        
                        logging.info(f"Processing device: {hostname} ({aid})")
                        
                        # Get vulnerabilities
                        vuln_ids = self.get_vulnerabilities_for_aid(aid)
                        if not vuln_ids:
                            logging.info(f"No vulnerabilities found for {hostname}")
                            continue
                            
                        # Process vulnerabilities
                        dedup_vulns = self.process_vulnerabilities(vuln_ids)
                        
                        if dedup_vulns:
                            # Generate and print email content
                            email_content = self.generate_email_content(hostname, dedup_vulns)
                            print(f"\nEmail would be sent to: {email}")
                            print("=" * 50)
                            print(email_content)
                            print("=" * 50)
                        else:
                            logging.info(f"No actionable vulnerabilities found for {hostname}")
                            
                        time.sleep(1)  # Rate limiting between devices
                        
        except Exception as e:
            logging.error(f"Error processing devices: {str(e)}")

def main():
    try:
        notifier = VulnerabilityNotifier()
        
        # First, update device mappings
        logging.info("Updating device mappings...")
        notifier.create_csv_if_not_exists()
        notifier.update_device_mappings()
        
        # Then process vulnerabilities for all devices
        logging.info("Processing vulnerabilities for all devices...")
        notifier.process_all_devices()
        
    except Exception as e:
        logging.error(f"Fatal error in main execution: {str(e)}")

if __name__ == "__main__":
    main()
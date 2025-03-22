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
        #Initialize CSV file if it doesn't exist
        if not self.csv_path.exists():
            with open(self.csv_path, 'w', newline='', encoding='utf-8') as file:
                writer = csv.DictWriter(file, fieldnames=['AID', 'hostname', 'email address'])
                writer.writeheader()
            logger.info(f"Created new CSV file: {self.csv_path}")

    def get_devices(self):
        # Fetch all host AIDs
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
        # Update device mapping CSV, whilst preserving entries
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
        """
        Get vulnerabilities for a specific AID using scroll pagination.
        Retrieves vulnerabilities in order of priority: CRITICAL, then HIGH, then MEDIUM,
        until at least 5 unique applications are found or all priority levels are checked.
        """
        # Base filter components that will be used in all queries
        # Edit where applicable i.e. you may wish to include a filter for actively exploited only
        base_filter_components = {
            "AID": f"aid:'{aid}'",
            "OpenV": "status:!'closed'",
            "Remediation_Possible": "cve.remediation_level:'O'"
        }
        
        # Priority levels in order of importance
        priority_levels = ["CRITICAL", "HIGH", "MEDIUM"]
        
        combined_vuln_ids = []
        unique_products = set()
        
        # Process each priority level one by one until we have at least 5 applications or run out of levels
        for priority in priority_levels:
            # If we already have 5 or more unique products, we can stop
            if len(unique_products) >= 5:
                logger.debug(f"Already found {len(unique_products)} unique products before checking {priority} vulnerabilities")
                break
                
            logger.debug(f"Retrieving {priority} vulnerabilities for AID {aid}")
            
            # Create a new filter string for the current priority level
            current_filter_components = base_filter_components.copy()
            current_filter_components["ExPRT"] = f"cve.exprt_rating:'{priority}'"
            filter_string = "+".join(current_filter_components.values())
            
            # Retrieve vulnerabilities for the current priority level
            vuln_ids = self._retrieve_vulnerabilities_with_pagination(aid, filter_string)
            
            if vuln_ids:
                combined_vuln_ids.extend(vuln_ids)
                
                # Process these vulnerabilities to see if we now have enough unique products
                temp_products = self._get_unique_products_from_vulns(vuln_ids)
                unique_products.update(temp_products)
                
                logger.debug(f"After processing {priority} vulnerabilities: {len(unique_products)} unique products found")
        
        logger.debug(f"Total unique vulnerabilities fetched for AID {aid} across all priority levels: {len(combined_vuln_ids)}")
        return combined_vuln_ids

    def _retrieve_vulnerabilities_with_pagination(self, aid, filter_string):
        # Helper method to retrieve vulnerabilities using pagination.
        all_vuln_ids = []
        limit = 100  # vulnerabilities per page
        scroll_after = None
        total_vulns = None
        iteration_count = 0
        max_iterations = 7  # 700 CVE ID soft limit - Safeguard against infinite loops

        try:
            # Initial request with scrolling enabled
            response = self.falcon_vuln.query_vulnerabilities(
                filter=filter_string,
                limit=limit,
                scroll=True
            )

            if response["status_code"] != 200:
                logger.error(f"Error querying vulnerabilities for AID {aid}: {response['status_code']} - Response: {response}")
                return []

            resources = response["body"].get("resources", [])
            all_vuln_ids.extend(resources)
            pagination = response["body"].get("meta", {}).get("pagination", {})
            total_vulns = pagination.get("total")
            scroll_after = pagination.get("after")
            logger.debug(f"Fetched {len(resources)} vulnerabilities for AID {aid} in the first batch. Total reported: {total_vulns}")

            # Track unique IDs seen so far to avoid duplicates
            seen_ids = set(resources)

            # Continue pagination only if we have more results to fetch and a valid scroll token
            while scroll_after and (len(all_vuln_ids) < total_vulns) and (iteration_count < max_iterations):
                iteration_count += 1
                
                # Use the scroll parameter correctly
                response = self.falcon_vuln.query_vulnerabilities(
                    filter=filter_string,
                    limit=limit,
                    scroll=True,
                    after=scroll_after
                )

                if response["status_code"] != 200:
                    logger.error(f"Error during scrolling for AID {aid}: {response['status_code']}")
                    break

                resources = response["body"].get("resources", [])
                if not resources:
                    logger.debug("No resources returned in this scroll batch; ending pagination.")
                    break

                # Only add new IDs to avoid duplicates
                new_ids = [id for id in resources if id not in seen_ids]
                seen_ids.update(new_ids)
                all_vuln_ids.extend(new_ids)
                
                logger.debug(f"Fetched {len(resources)} vulnerabilities in batch {iteration_count + 1}, added {len(new_ids)} new IDs. Total unique: {len(seen_ids)}")
                
                pagination = response["body"].get("meta", {}).get("pagination", {})
                new_scroll_after = pagination.get("after")

                # If the 'after' value is unchanged or empty, exit the loop
                if not new_scroll_after or new_scroll_after == scroll_after:
                    logger.debug("'After' value did not change; ending pagination.")
                    break

                scroll_after = new_scroll_after

            return list(seen_ids)

        except Exception as e:
            logger.exception(f"Error querying vulnerabilities for AID {aid}: {str(e)}")
            return []

    def _get_unique_products_from_vulns(self, vuln_ids):
        """
        Helper method to get unique product names from a list of vulnerability IDs.
        Returns a set of product names.
        """
        unique_products = set()
        
        if not vuln_ids:
            return unique_products
            
        batch_size = 10
        for i in range(0, len(vuln_ids), batch_size):
            batch = vuln_ids[i:i+batch_size]
            
            try:
                vuln_details = self.falcon_vuln.get_vulnerabilities(ids=batch)
                
                if vuln_details["status_code"] == 200:
                    for vuln in vuln_details["body"]["resources"]:
                        product_name = vuln.get('apps', [{}])[0].get('product_name_version', 'N/A')
                        
                        if product_name != 'N/A':
                            unique_products.add(product_name)
                
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Error processing vulnerability batch: {str(e)}")
                continue
        
        return unique_products

    def process_vulnerabilities(self, vuln_ids):
        """Process vulnerability details and return deduplicated results"""
        if not vuln_ids:
            logger.debug("No vulnerability IDs to process")
            return {}
            
        logger.debug(f"Processing {len(vuln_ids)} unique vulnerability IDs")
        dedup_vulns = defaultdict(lambda: {'cves': set(), 'severity': '', 'expert_rating': '', 'action': ''})
        severity_order = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
        
        batch_size = 10
        for i in range(0, len(vuln_ids), batch_size):
            batch = vuln_ids[i:i+batch_size]
            logger.debug(f"Processing batch {i//batch_size + 1} of {(len(vuln_ids) + batch_size - 1)//batch_size}")
            
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
                
        logger.debug(f"Vulnerability processing complete. Found {len(dedup_vulns)} unique products with vulnerabilities.")
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
            <title>Software Update Required</title>
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
                                    <p style="text-align: center;">We've identified vulnerable software installed on your device. Help us protect our organization by updating the following applications as soon as possible:</p>
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
                                    <p style="margin: 0;">Thank you for helping keep us secure.</p>
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

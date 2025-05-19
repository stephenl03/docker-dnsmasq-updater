import sys
import request
from typing import Any
from types import SimpleNamespace


from docker_udm_dns.shared.logging import get_logger
from docker_udm_dns.shared.resettable_timer import ResettableTimer

class UDMHandler:
    """Handle adding/removing A records on a UDM device via its Network API."""

    def __init__(self, temp_file, **kwargs):
        """Initialize UDMHandler with API details and timing."""
        self.params = SimpleNamespace(**kwargs)
        self.temp_file = temp_file
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.delayed_put = ResettableTimer(self.params.delay, self.put_hostfile)
        self.udm_url = f"https://{self.params.udm_api_address}/proxy/network/v2/api/site/default/static-dns"
        self.headers = {
            "X-API-KEY": self.params.udm_api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def queue_put(self):
        """Queue the addition of A records."""
        self.logger.info("Queued UDM A record update.")
        self.delayed_put.reset()

    def get_udm_records(self) -> list:
        try:
            response = requests.get(self.udm_url, headers=self.headers, verify=False)
            response.raise_for_status()
            dns_records = response.json()  # Assuming records are stored as JSON
            self.logger.debug("DNS records retrieved: %s", str(dns_records))
            return dns_records
        except Exception as e:
            self.logger.error("Error retrieving current UDM A records: %s", str(e))
            raise

    def get_temp_file_content(self) -> Any:
        with open(self.temp_file.name, 'r', encoding="utf-8") as temp_file:
            record = temp_file.read()
            self.logger.debug("Temp file contents: %s", record)
            return record

    def put_hostfile(self) -> None:
        """Add A records to the UDM device."""
        dns_records = self.get_udm_records()
        temp_file_content = self.get_temp_file_content()
        try:
            record = {
                "record_type": "A",
                "value": self.params.ip,  # IP address
                "key": "",  # Hostname
                "enabled": True
            }
            existing_record = [record for record in dns_records if record["key"] == ""]
            if existing_record:
                record.update(existing_record[0])

            self.logger.debug("Record, %s", str(record))
            response = requests.post(self.udm_url, headers=self.headers, json=record, verify=False)
            if response.ok:
                self.logger.info("Successfully added A record: %s", record['key'])
            else:
                self.logger.error("Failed to add A record: %s. Response: %s",
                                    record['key'], response.text)
        except Exception as e:
            self.logger.error("Error updating UDM A records: %s", str(e))

    def exec_restart_command(self):
        """Restart the UDM DNS service if needed."""
        # UDM devices may not require an explicit restart command for DNS changes.
        self.logger.info("No explicit restart required for UDM.")

import requests
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

    def put_hostfile(self):
        """Add A records to the UDM device."""
        try:
            response = requests.get(self.udm_url, headers=self.headers, verify=False)
            response.raise_for_status()
            dns_records = response.json()  # Assuming records are stored as JSON
            self.logger.debug("DNS records retrieved: %s", str(dns_records))
        except Exception as e:
            self.logger.error("Error retrieving current UDM A records: %s", str(e))

        try:
            payload = {
                "record_type": "A",
                "value": "",  # IP address
                "key": "",  # Hostname
                "enabled": True
            }
            existing_record = [record for record in dns_records if record["key"] == ""]
            if existing_record:
                payload.update(existing_record[0])

            response = requests.post(self.udm_url, headers=self.headers, json=payload, verify=False)
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

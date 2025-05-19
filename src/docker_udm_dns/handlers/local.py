import subprocess
from types import SimpleNamespace


from docker_udm_dns.shared.logging import get_logger
from docker_udm_dns.shared.resettable_timer import ResettableTimer


BLOCK_START = '### docker dnsmasq updater start ###'
BLOCK_END = '### docker dnsmasq updater end ###'

class LocalHandler():
    """Handle writing of a local hosts file."""

    def __init__(self, temp_file, **kwargs):
        """Initialize timing."""
        self.params = SimpleNamespace(**kwargs)
        self.temp_file = temp_file
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.delayed_put = ResettableTimer(self.params.delay, self.put_hostfile)

    def queue_put(self):
        """Delayed writing of the hosts file, allowing for multiple proximate events."""
        self.logger.info('Queued hosts file update.')
        self.delayed_put.reset()

    def put_hostfile(self):
        """Copy the temporary hosts file over the top of the real file."""
        self.logger.info('Writing hosts file: %s', self.params.file)

        try:
            with open(self.temp_file.name, 'r', encoding='utf-8') as temp_file:
                hosts = temp_file.read()
            with open(self.params.file, 'w', encoding='utf-8') as hosts_file:
                hosts_file.write(str(BLOCK_START + '\n' + hosts + BLOCK_END + '\n'))
        except FileNotFoundError as err:
            self.logger.error('Error writing hosts file: %s', err)

        self.exec_restart_command()

    def exec_restart_command(self):
        """Execute command to restart dnsmasq on the local device."""
        restart_cmd = self.params.restart_cmd.strip('\'"')

        try:
            subprocess.run(restart_cmd.split(), check=True)
        except subprocess.CalledProcessError:
            self.logger.error(
                'CalledProcessError: Failed to execute restart command: %s', restart_cmd
            )
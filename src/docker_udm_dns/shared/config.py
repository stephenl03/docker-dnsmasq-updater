import argparse
import os
import logging
import json
import ipaddress
import sys

from docker_udm_dns.shared.logging import get_logger

CONFIG_FILE = 'dnsmasq_updater.conf'
CONFIG_PATHS = [os.path.dirname(os.path.realpath(__file__)), '/etc/', '/conf/']


class ConfigHandler():
    """Read config files and parse commandline arguments."""

    log_level = os.getenv("DEFAULT_LOG_LEVEL", logging.INFO)

    def __init__(self):
        """Initialize default config, parse config file and command line args."""
        self.defaults = {
            'config_file': CONFIG_FILE,
            'domain': 'docker',
            'labels_from': None,
            'prepend_www': False,
            'docker_socket': 'unix://var/run/docker.sock',
            'network': '',
            'server': '',
            'port': '22',
            'login': '',
            'password': '',
            'key': '',
            'file': '',
            'restart_cmd': '',
            'mode': 'standalone',
            'location': 'remote',
            'api_address': '0.0.0.0',
            'api_port': '8080',
            'api_key': '',
            'api_backend': None,
            'log_level': self.log_level,
            'delay': 10,
            'local_write_delay': 3,
            'ready_fd': ''
        }

        self.args = []
        self.config_parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=__doc__, add_help=False)

        self.parse_initial_config()
        self.parse_config_file()
        self.parse_command_line()
        self.check_args()

    def parse_initial_config(self):
        """Just enough argparse to specify a config file and a debug flag."""
        self.config_parser.add_argument(
            '-c', '--config_file', action='store', metavar='FILE',
            help='external configuration file')
        self.config_parser.add_argument(
            '--debug', action='store_true', help='turn on debug messaging')

        self.args = self.config_parser.parse_known_args()[0]

        if self.args.debug:
            self.log_level = logging.DEBUG
            self.defaults['log_level'] = logging.DEBUG

        self.logger = get_logger(self.__class__.__name__, self.log_level)
        self.logger.debug('Initial args: %s', json.dumps(vars(self.args), indent=4))

    def parse_config_file(self):
        """Find and read external configuration files, if they exist."""
        self.logger.debug('self.args.config_file: %s', self.args.config_file)

        # find external configuration if none is specified
        if self.args.config_file is None:
            for config_path in CONFIG_PATHS:
                config_file = os.path.join(config_path, CONFIG_FILE)
                self.logger.debug('Looking for config file: %s', config_file)
                if os.path.isfile(config_file):
                    self.logger.info('Found config file: %s', config_file)
                    self.args.config_file = config_file
                    break

        if self.args.config_file is None:
            self.logger.info('No config file found.')

        # read external configuration if specified and found
        if self.args.config_file is not None:
            if os.path.isfile(self.args.config_file):
                config = configparser.ConfigParser()
                config.read(self.args.config_file)
                self.defaults.update(dict(config.items("general")))
                self.defaults.update(dict(config.items("dns")))
                self.defaults.update(dict(config.items("hosts")))
                self.defaults.update(dict(config.items("docker")))
                self.defaults['prepend_www'] = config['dns'].getboolean('prepend_www')
                self.defaults.update(dict(config.items("api")))

                self.logger.debug('Args from config file: %s', json.dumps(self.defaults, indent=4))
            else:
                self.logger.error('Config file (%s) does not exist.',
                                  self.args.config_file)

    @staticmethod
    def parse_commas(this_string):
        """Convert a comma separated string into a list variable."""
        if this_string:
            return this_string.split(',')
        return None

    def parse_command_line(self):
        """
        Parse command line arguments.

        Overwrite the default config and anything found in a config file.
        """
        parser = argparse.ArgumentParser(
            description='Docker Dnsmasq Updater', parents=[self.config_parser])
        parser.set_defaults(**self.defaults)

        parser.add_argument(
            '--local_write_delay', action='store', type=int, help=argparse.SUPPRESS)
        parser.add_argument(
            '--ready_fd', action='store', metavar='INT',
            help='set to an integer to enable signalling readiness by writing '
            'a new line to that integer file descriptor')

        mode_group = parser.add_argument_group(title='Mode')
        mode = mode_group.add_mutually_exclusive_group()
        mode.add_argument(
            '--standalone', action='store_const', dest='mode', const='standalone',
            help='running on a standalone Docker host (default)')
        mode.add_argument(
            '--manager', action='store_const', dest='mode', const='manager',
            help='bring up the API and run as the manager for multiple Docker nodes')

        docker_group = parser.add_argument_group(title='Docker')
        docker_group.add_argument(
            '-D', '--docker_socket', action='store', metavar='SOCKET',
            help='path to the docker socket (default: \'%(default)s\')')
        docker_group.add_argument(
            '-n', '--network', action='store', metavar='NETWORK',
            help='Docker network to monitor')

        dns_group = parser.add_argument_group(title='DNS')
        dns_group.add_argument(
            '-i', '--ip', action='store', metavar='IP',
            help='default IP for the DNS records')
        dns_group.add_argument(
            '-d', '--domain', action='store', metavar='DOMAIN',
            help='domain/zone for the DNS record (default: \'%(default)s\')')
        dns_group.add_argument(
            '-L', '--labels_from', action='store', metavar='PROXIES', type=self.parse_commas,
            help='add hostnames from labels set by other services (standalone only, default: \'%(default)s\')')
        dns_group.add_argument(
            '-w', '--prepend_www', action='store_true',
            help='add \'www\' subdomains for all hostnames')

        hosts_group = parser.add_argument_group(title='hosts file')
        location_group = hosts_group.add_mutually_exclusive_group()
        location_group.add_argument(
            '--remote', action='store_const', dest='location', const='remote',
            help='write to a remote hosts file, via SSH (default)')
        location_group.add_argument(
            '--local', action='store_const', dest='location', const='local',
            help='write to a local hosts file')
        hosts_group.add_argument(
            '-f', '--file', action='store', metavar='FILE',
            help='the hosts file (including path) to write')
        hosts_group.add_argument(
            '-r', '--restart_cmd', action='store', metavar='COMMAND',
            help='the dnsmasq restart command to execute')
        hosts_group.add_argument(
            '-t', '--delay', action='store', metavar='SECONDS', type=int,
            help='delay for writes to the hosts file (default: \'%(default)s\')')

        remote_hosts_group = parser.add_argument_group(
            title='Remote hosts file (needed by --remote)')
        remote_hosts_group.add_argument(
            '-s', '--server', action='store', metavar='SERVER',
            help='dnsmasq server address')
        remote_hosts_group.add_argument(
            '-P', '--port', action='store', metavar='PORT',
            help='port for SSH on the dnsmasq server (default: \'%(default)s\')')
        remote_hosts_group.add_argument(
            '-l', '--login', action='store', metavar='USERNAME',
            help='login name for the dnsmasq server')
        remote_hosts_group.add_argument(
            '-k', '--key', action='store', metavar='FILE',
            help='identity/key file for SSH to the dnsmasq server')
        remote_hosts_group.add_argument(
            '-p', '--password', action='store', metavar='PASSWORD',
            help='password for the dnsmasq server OR for an encrypted SSH key')

        api_group = parser.add_argument_group(
            title='API server (needed by --manager)')
        api_group.add_argument(
            '--api_address', action='store', metavar='IP',
            help='address for API to listen on (default: \'%(default)s\')')
        api_group.add_argument(
            '--api_port', action='store', metavar='PORT',
            help='port for API to listen on (default: \'%(default)s\')')
        api_group.add_argument(
            '--api_key', action='store', metavar='KEY', help='API access key')
        api_group.add_argument(
            '--api_backend', action='store', metavar='STRING',
            help='API backend (refer to Bottle module docs for details)')

        self.args = parser.parse_args()
        self.logger.debug('Parsed command line:\n%s',
                          json.dumps(vars(self.args), indent=4))

    def check_args(self):
        # pylint: disable=too-many-branches
        """Check we have all the information we need to run."""
        if self.args.ip == '':
            self.logger.error('No host IP specified.')
            sys.exit(1)

        try:
            ipaddress.ip_address(self.args.ip)
        except ValueError:
            self.logger.error('Specified host IP (%s) is invalid.', self.args.ip)
            sys.exit(1)

        if self.args.file == '':
            self.logger.error('No hosts file specified.')
            sys.exit(1)

        if self.args.restart_cmd == '':
            self.logger.error('No dnsmasq restart command specified.')
            sys.exit(1)

        if not isinstance(self.args.delay, int):
            self.logger.error('Specified delay (%s) is invalid.', self.args.delay)
            sys.exit(1)

        if self.args.location == 'remote':
            if self.args.login == '':
                self.logger.error('No remote login name specified.')
                sys.exit(1)

            if self.args.key == '':
                if self.args.password == '':
                    self.logger.error('No remote password or key specified.')
                    sys.exit(1)
            elif not os.path.exists(self.args.key):
                self.logger.error('Key file (%s) does not exist.', self.args.key)
                sys.exit(1)

            if self.args.server == '':
                self.logger.error('No remote server specified.')
                sys.exit(1)

        if self.args.mode == 'manager' and self.args.api_key == '':
            self.logger.error('No manager API key specified.')
            sys.exit(1)

    def get_args(self):
        """Return all config parameters."""
        return self.args
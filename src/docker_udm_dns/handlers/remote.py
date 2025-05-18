from types import SimpleNamespace


from docker_udm_dns.shared.logging import get_logger
from docker_udm_dns.shared.resettable_timer import ResettableTimer


class RemoteHandler():
    """Handle getting/putting/cleaning of local and remote hosts files."""

    def __init__(self, temp_file, **kwargs):
        """Initialize SSH client, temp file and timing."""
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.temp_file = temp_file
        self.ssh = SSHClient()
        self.ssh.set_missing_host_key_policy(AutoAddPolicy())
        self.delayed_put = ResettableTimer(self.params.delay, self.put_hostfile)
        self.key = False

        self.get_server_ip()

        if self.params.key != '':
            self.logger.debug('self.params.key: %s', self.params.key)
            self.verify_key()

    def get_server_ip(self):
        """
        Check for a valid dnsmasq server IP to use.

        We can't use a hostname for the server because we end up trying to do a
        DNS lookup immediately after instructing dnsmasq to restart.
        """
        try:
            ipaddress.ip_address(self.params.server)
            self.params.server_ip = self.params.server
        except ValueError:
            try:
                self.params.server_ip = socket.getaddrinfo(self.params.server, None)[0][4][0]
            except (ValueError, socket.gaierror):
                self.logger.error('Server (%s) cannot be found.', self.params.server)
                sys.exit(1)

    def verify_key(self):
        """Verify and open key file or error on failure."""
        self.check_key('RSA')
        if not self.key:
            self.check_key('DSA')
            if not self.key:
                self.logger.error('No usable RSA or DSA key found. Halting.')
                sys.exit(1)

    def check_key(self, algorithm):
        """Set self.key if self.params.key is valid for the algorithm."""
        if algorithm == 'RSA':
            algo_class = RSAKey
        elif algorithm == 'DSA':
            algo_class = DSSKey
        else:
            raise ValueError('check_key() works with \'RSA\' or \'DSA\' only.')

        self.logger.debug('Testing if key is %s.', algorithm)
        try:
            key = algo_class.from_private_key_file(self.params.key)
        except PasswordRequiredException:
            if self.params.password != '':
                self.logger.debug('Decrypting %s key.', algorithm)
                try:
                    key = algo_class.from_private_key_file(
                        self.params.key, password=self.params.password)
                except SSHException:
                    self.logger.error('Password for key is not valid.')
                else:
                    self.logger.info('Found valid encrypted %s key.', algorithm)
                    self.key = key
            else:
                self.logger.error('Encrypted %s key, requires password.', algorithm)
        except SSHException:
            self.key = False
        else:
            self.logger.info('Found valid %s key.', algorithm)
            self.key = key

    def open_ssh(self):
        """Check if an SSH connection is open, open a new connection if not."""
        try:
            transport = self.ssh.get_transport()
            transport.send_ignore()
        except (EOFError, AttributeError):
            self.logger.debug('Opening SSH connection.')

            pass_params = {}
            pass_params['username'] = self.params.login

            if self.key:
                pass_params['pkey'] = self.key
            else:
                pass_params['password'] = self.params.password

            try:
                self.ssh.connect(self.params.server_ip, **pass_params)
            except AuthenticationException:
                self.logger.error('Could not authenticate with remote device.')
                sys.exit(1)
            except BadHostKeyException:
                self.logger.error('Host key does not match expected key.')
                sys.exit(1)

    def close_ssh(self):
        """Close the SSH connection."""
        if self.ssh:
            self.logger.debug('Closing SSH connection.')
            self.ssh.close()

    def queue_put(self):
        """
        Delayed putting of the local hosts file on the remote device.

        The delay allows for any additional changes in the immediate future,
        such as expected when a container is restarting, for example.
        """
        self.logger.info('Queued remote hosts file update.')
        self.delayed_put.reset()

    def put_hostfile(self):
        """Put the local hosts file on the remote device."""
        self.open_ssh()
        self.logger.info('Writing remote hosts file: %s', self.params.file)

        with open(self.temp_file.name, 'r', encoding="utf-8") as temp_file:
            hosts_block = BLOCK_START + '\n' + temp_file.read() + BLOCK_END

            try:
                exec_return = self.ssh.exec_command(
                    'echo -e "' + hosts_block + '" >' + self.params.file)[1]
                if exec_return.channel.recv_exit_status():
                    self.logger.error('Could not write hosts file.')
                else:
                    self.exec_restart_command()
            except EOFError:
                self.logger.error('Could not write hosts file.')

        self.close_ssh()

    def exec_restart_command(self):
        """Execute command to update dnsmasq on remote device."""
        self.open_ssh()
        restart_cmd = self.params.restart_cmd.strip('\'"')

        try:
            exec_return = self.ssh.exec_command(restart_cmd)[1]
        except SSHException:
            self.logger.error('SSHException: Failed to execute remote command: %s', restart_cmd)

        if exec_return.channel.recv_exit_status() > 0:
            self.logger.error('Could not execute remote command: %s', restart_cmd)
        else:
            self.logger.info('Executed remote command: %s', restart_cmd)

from types import SimpleNamespace

from docker_udm_dns.shared.logging import get_logger

class DockerHandler():
    """Handle connecting to the Docker socket and the data it produces."""

    client = None

    def __init__(self, hosts_handler, **kwargs):
        """Initialize variables, do nothing until start_monitor()."""
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.hosts_handler = hosts_handler
        self.scan_success = False

        self.event_verbs = {'start': 'starting',
                            'stop': 'stopping',
                            'connect': 'connecting to',
                            'disconnect': 'disconnecting from'}

        if self.params.ready_fd == '':
            self.ready_fd = False
        else:
            self.ready_fd = int(self.params.ready_fd)

    def get_client(self):
        """Create the Docker client object."""
        try:
            self.client = docker.DockerClient(base_url=self.params.docker_socket)
        except docker.errors.DockerException as err:
            self.logger.error('Could not open Docker socket at %s. Exiting.',
                              self.params.docker_socket)
            self.logger.debug('Error: %s', err)
            sys.exit(1)

        self.logger.info('Connected to Docker socket.')

        swarm_status = self.client.info()['Swarm']['LocalNodeState']
        match swarm_status:
            case 'inactive':
                self.logger.info('Docker standalone detected.')
            case 'active':
                self.logger.info('Docker Swarm mode detected.')
                if self.params.mode != 'manager':
                    # pylint: disable=line-too-long
                    self.logger.error('Can only run in a Swarm as a manager, run with `--manager` argument')
                    self.logger.error('Use `dnsmasq_updater_agent.py` for monitoring Swarm devices.')
                    # pylint: enable=line-too-long
                    self.logger.error('Exiting.')
                    sys.exit(2)
            case _:
                self.logger.error('Swarm detection failed: %s', swarm_status)
                sys.exit(1)

    def get_hostnames(self, container):
        """
        Return a list of hostnames for a container or service.

        Include any IP address override in the form '<hostname>:<address>'
        """
        hostnames = [container.attrs['Config']['Hostname']]
        labels = container.labels

        try:
            hostnames.append(labels['dnsmasq.updater.host'])
        except KeyError:
            pass

        if self.params.labels_from is not None:
            traefik_pattern = re.compile(r'Host\(`([^`]*)`\)')
            for key, value in labels.items():
                if 'traefik' in self.params.labels_from and key.startswith('traefik.http.routers.'):
                    for match in traefik_pattern.finditer(value):
                        hostnames.append(match.group(1))

        ip = self.get_hostip(container)
        if ip is not None:
            hostnames = [x + ':' + ip for x in hostnames]

        try:
            extra_hosts = container.attrs['HostConfig']['ExtraHosts']
        except KeyError:
            pass
        else:
            if extra_hosts:
                hostnames = hostnames + extra_hosts

        return hostnames

    def get_hostip(self, container):
        """Get any IP address set with a label."""
        try:
            return container.labels['dnsmasq.updater.ip']
        except KeyError:
            return None

    def scan_runnning_containers(self):
        """Scan running containers, find any with dnsmasq.updater.enable."""
        self.logger.info('Started scanning running containers.')

        try:
            containers = self.client.containers.list(
                filters={"label": "dnsmasq.updater.enable", "status": "running"})
        except docker.errors.APIError as err:
            self.logger.warning('Could not scan running containers: %s', err)
            return

        for container in containers:
            hostnames = self.get_hostnames(container)
            if hostnames is None:
                continue
            self.logger.info('Found %s: %s', container.name, ', '.join(hostnames))
            if self.hosts_handler.add_hosts(container.short_id, hostnames, do_write=False):
                self.scan_success = True

        self.logger.info('Finished scanning running containers.')

    def scan_network_containers(self):
        """Scan all containers on a specified network."""
        self.logger.info('Started scanning containers on \'%s\' network.', self.params.network)

        try:
            network = self.client.networks.get(self.params.network)
        except docker.errors.NotFound:
            self.logger.error(
                'Cannot scan network: network \'%s\' does not exist.', self.params.network)
            return

        for container in network.attrs['Containers']:
            try:
                container_object = self.client.containers.get(container)
            except docker.errors.NotFound:
                continue

            hostnames = self.get_hostnames(container_object)
            self.logger.info('Found %s: %s', container_object.name, ', '.join(hostnames))
            if self.hosts_handler.add_hosts(container_object.short_id, hostnames):
                self.scan_success = True

        self.logger.info('Finished scanning containers on \'%s\' network.', self.params.network)

    def handle_container_event(self, event):
        """Handle a container event."""
        if 'dnsmasq.updater.enable' not in event['Actor']['Attributes']:
            return

        container = self.client.containers.get(event['Actor']['ID'])
        short_id = container.short_id
        name = container.name

        self.logger.info('Detected %s %s.', name, self.event_verbs[event['status']])

        if event['status'] == 'stop':
            self.hosts_handler.del_hosts(short_id)
        elif event['status'] == 'start':
            hostnames = self.get_hostnames(container)
            if hostnames is not None:
                self.hosts_handler.add_hosts(short_id, hostnames)

    def handle_network_event(self, event):
        """Handle a network event."""
        try:
            container = self.client.containers.get(event['Actor']['Attributes']['container'])
        except docker.errors.NotFound:
            self.logger.warning(
                'Container %s not found.', event['Actor']['Attributes']['container'])
            container = None

        if container is not None:
            short_id = container.short_id

            self.logger.info('Detected %s %s \'%s\' network.', container.name,
                             self.event_verbs[event['Action']],
                             event['Actor']['Attributes']['name'])

            if event['Action'] == 'disconnect':
                self.hosts_handler.del_hosts(short_id)
            elif event['Action'] == 'connect':
                self.hosts_handler.add_hosts(short_id, self.get_hostnames(container))

    def handle_events(self, event):
        """Monitor the docker socket for relevant container and network events."""
        if (event['Type'] == 'container') and (event['status'] in {'start', 'stop'}):
            self.handle_container_event(event)

        elif (event['Type'] == 'network') \
            and (self.params.network in event['Actor']['Attributes']['name']) \
                and (event['Action'] in {'connect', 'disconnect'}):
            self.handle_network_event(event)

    def start_monitor(self):
        """
        Connect to Docker socket.

        Process existing containers then monitor events.
        """
        self.get_client()
        self.scan_runnning_containers()

        if self.params.network:
            self.scan_network_containers()
        if self.scan_success:
            self.hosts_handler.queue_write()

        events = self.client.events(decode=True)
        signal_ready(self.ready_fd, self.logger)

        while True:
            for event in events:
                self.handle_events(event)
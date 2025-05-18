from types import SimpleNamespace

from bottle import Bottle, request, response  # type: ignore[import-untyped, import-not-found]

from docker_udm_dns.shared.logging import get_logger

class APIServerHandler(Bottle):
    """Run the API server."""

    def __init__(self, hosts_handler, **kwargs):
        """Initislize the API and configure routes."""
        super().__init__()
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.hosts_handler = hosts_handler

        if self.params.ready_fd == '':
            self.ready_fd = False
        else:
            self.ready_fd = int(self.params.ready_fd)

        self.install(JwtPlugin(self.validation, self.params.api_key, algorithm="HS512"))
        self.permissions = {"user": 0, "service": 1, "admin": 2}

        self.route('/auth', callback=self.auth, method='POST')
        self.route('/status', callback=self.status)
        self.route('/add', callback=self.add_hosts, method='POST', auth='user')
        self.route('/del/<short_id>', callback=self.del_hosts, method='DELETE', auth='user')

        self.instance_id = hash(time.time())

        signal_ready(self.ready_fd, self.logger)

    def validation(self, auth, user):
        """Validate request."""
        return self.permissions[auth["type"]] >= self.permissions[user]

    def auth(self):
        """
        Authenticate a node.

        request: {'clientId': <client_id>, 'clientSecret': <password>}
        response: {'access_token': <token>, 'type': 'bearer'}
        """
        client_id = request.headers.get('clientId')
        client_secret = request.headers.get('clientSecret')

        try:
            kdf = Scrypt(salt=str.encode(client_id), length=32, n=2**14, r=8, p=1)
        except TypeError as err:
            self.logger.error('Invalid auth request: %s', err)
            response.status = 401
            return "Unauthorized."

        try:
            kdf.verify(str.encode(self.params.api_key), bytes.fromhex(client_secret))
        except cryptography.exceptions.InvalidKey as err:
            self.logger.warning('Invalid key from client %s: %s', client_id, err)
            response.status = 401
            return "Unauthorized."

        user = {"client_id": client_id, "client_secret": client_secret, "type": "user"}

        if not user:
            raise self.HTTPError(403, "Invalid user or password")
        user["exp"] = time.time() + 86400
        return {"access_token": JwtPlugin.encode(user), "type": "bearer"}

    def status(self):
        """
        Return the instance ID.

        This is a general up/ready indicator, as well as providing a unique ID
        so the clients can tell if the API has restarted (and re-initialize the
        hosts data accordingly).
        """
        # self.logger.debug('Status check: %s', request.remote_addr)
        response.add_header('DMU-API-ID', self.instance_id)
        return str(self.instance_id)

    def add_hosts(self):
        """Add new hosts."""
        self.logger.debug('add_hosts: %s', request.json)
        self.hosts_handler.add_hosts(request.json['short_id'],
                                     request.json['hostnames'],
                                     request.json.get('from', None))
        response.add_header('DMU-API-ID', self.instance_id)
        return str(self.instance_id)

    def del_hosts(self, short_id):
        """Delete hosts."""
        self.logger.debug('del_hosts: %s', short_id)
        self.hosts_handler.del_hosts(short_id)

        response.status = 204
        response.add_header('DMU-API-ID', self.instance_id)
        return str(self.instance_id)

    def start_monitor(self):
        """
        Run the API.

        Clear sys.argv before calling run(), else args get sent to the backend.
        """
        self.logger.info('Starting API..')

        sys.argv = sys.argv[:1]
        if self.params.api_backend is None:
            self.run(host=self.params.api_address, port=self.params.api_port,
                     debug=self.params.debug)
        else:
            self.run(host=self.params.api_address, server=self.params.api_backend,
                     port=self.params.api_port, debug=self.params.debug)

import logging
import re

from types import SimpleNamespace
from python_hosts import Hosts, HostsEntry
from collections import defaultdict

from docker_udm_dns.shared.logging import get_logger
from docker_udm_dns.shared.resettable_timer import ResettableTimer

class HostsHandler():
    """Handle the Hosts object and the individual HostEntry objects."""

    def __init__(self, output_handler, **kwargs):
        """Initialize file handler and timing."""
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.output_handler = output_handler
        self.temp_file = output_handler.temp_file
        self.delayed_write = ResettableTimer(self.params.local_write_delay, self.write_hosts)
        self.hosts = Hosts(path='/dev/null')

    def parse_hostnames(self, hostnames, id_string):
        """
        Return dictionary items containing IPs and a list of hostnames.

        dict_items([('<IP_1>', ['<hostname1>', '<hostname2>', etc..]),
                    ('<IP_2>', ['<hostname3>', '<hostname4>', etc..]), etc..])
        """
        hostname_dict = defaultdict(set)

        for hostname in hostnames:
            host_ip = self.params.ip
            host_list = set()

            # extra-hosts will include the IP, separated by a colon
            if ':' in hostname:
                hostname, host_ip = hostname.split(':', 1)

            # strip the top level demain, if included
            try:
                hostname = hostname[0:hostname.index('.' + self.params.domain)]
            except ValueError:
                pass

            if not self.hosts.exists(comment=id_string):
                host_list.update([hostname, hostname + '.' + self.params.domain])

                if self.params.prepend_www and not re.search('^www', hostname):
                    host_list.update(['www.' + hostname + '.' + self.params.domain])
                hostname_dict[host_ip].update(host_list)
            else:
                self.logger.debug('comment exists in Hosts: %s', id_string)

        return dict([host_ip, sorted(hostnames)] for host_ip, hostnames in hostname_dict.items())

    def add_hosts(self, short_id, hostnames, agent_id=None, do_write=True):
        """
        Create host's HostsEntry, add it to Hosts object. Optionally write out.

        Setting the comment to a unique string (like a contaienr's 'short_id')
        makes it easy to delete the correct hosts (and only the correct hosts)
        across multiple IPs. Including an identifier for the particular Agent
        that added the host allows esay deletion for all that Agent's hosts if
        the Agent goes down.
        """
        id_string = short_id
        if agent_id is not None:
            id_string += '.' + agent_id

        parsed_hostnames = self.parse_hostnames(hostnames, id_string)
        parsed_items = parsed_hostnames.items()

        if not parsed_items:
            self.logger.debug('Added host(s): no hostnames to add: %s', short_id)
        else:
            try:
                for host_ip, names in parsed_items:
                    self.logger.debug('Adding: %s: %s', host_ip, ', '.join(names))
                    try:
                        hostentry = HostsEntry(entry_type='ipv4', address=host_ip,
                                               names=names, comment=id_string)
                    except python_hosts.exception.InvalidIPv4Address:
                        self.logger.error('Skipping invalid IP address: %s', host_ip)
                    else:
                        if self.params.mode == 'manager':
                            self.hosts.add([hostentry],
                                           allow_address_duplication=True,
                                           allow_name_duplication=True)
                        else:
                            self.hosts.add([hostentry], force=True,
                                           allow_address_duplication=True)

                if do_write:
                    self.queue_write()
                self.logger.info('Added host(s): %s',
                                 ', '.join(sum(parsed_hostnames.values(), [])))

            except ValueError as err:
                self.logger.info('Host already exists, nothing to add.')
                self.logger.debug(err)

        return parsed_items

    def del_hosts(self, id_string):
        """Delete hosts with a comment matching id_string."""
        hostnames = sum([entry.names for entry in self.hosts.entries
                         if id_string in entry.comment], [])

        if not hostnames:
            self.logger.debug(
                'Deleting host(s): no hostnames to delete: %s', id_string)
        else:
            self.logger.info('Deleting host(s): %s', ', '.join(hostnames))
            self.hosts.entries = list(
                set(self.hosts.entries) - {entry for entry in self.hosts.entries
                                           if id_string in entry.comment}
            )

            self.queue_write()

    def queue_write(self):
        """
        Delayed writing of the local and remote hosts files.

        The delay allows for any additional changes in the immediate future,
        such as expected when a container is restarting, for example.
        """
        self.delayed_write.reset()

    def write_hosts(self):
        """Write local hosts file, send it to the output handler."""
        if self.params.log_level == logging.DEBUG:
            self.logger.debug('Writing local hosts temp file: %s', self.temp_file.name)
            for entry in self.hosts.entries:
                print('    ', entry)

        self.hosts.write(path=self.temp_file.name)
        self.temp_file.seek(0)
        self.output_handler.queue_put()
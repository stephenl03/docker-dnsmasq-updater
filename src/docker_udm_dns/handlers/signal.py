import sys
import os

from types import SimpleNamespace

from docker_udm_dns.shared.logging import get_logger


class SignalHandler():
    """Handle signals."""
    # def __init__(self, **kwargs):
    #     """Initialize variables"""
    #     self.params = SimpleNamespace(**kwargs)
    #     self.logger = get_logger(self.__class__.__name__, self.params.log_level)

    @staticmethod
    def signal_handler(sig, _frame):
        """Handle SIGINT cleanly."""
        print('\nCaught signal:', sig, '\n')
        sys.exit(0)

    @staticmethod
    def signal_ready(ready_fd, logger):
        """Signal we're ready."""
        if ready_fd:
            logger.info('Initialization done. Signalling readiness.')
            logger.debug('Readiness signal writing to file descriptor %s.', ready_fd)

            try:
                os.write(ready_fd, '\n'.encode())
            except OSError:
                logger.warning('Could not signal file descriptor \'%s\'.', ready_fd)
        else:
            logger.info('Initialization done.')
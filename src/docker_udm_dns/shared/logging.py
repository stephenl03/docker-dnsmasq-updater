import logging
import os
import sys
import time

from typing import Dict


DEFAULT_LOG_LEVEL = logging.INFO
STDOUT_HANDLER = logging.StreamHandler(sys.stdout)
STDOUT_HANDLER.setFormatter(
    logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

loggers: Dict[str, str] = {}


class Formatter(logging.Formatter):
    """Format logger output."""

    def formatTime(self, record, datefmt=None):
        """Use system timezone and add milliseconds."""
        datefmt = f'%Y-%m-%d %H:%M:%S.{round(record.msecs):03d} ' + time.strftime('%z')
        return time.strftime(datefmt, self.converter(record.created))


def get_logger(class_name, log_level):
    """Get logger objects for individual classes."""
    name = os.path.splitext(os.path.basename(__file__))[0]
    if log_level == logging.DEBUG:
        name = '.'.join([name, class_name])

    if loggers.get(name):
        return loggers.get(name)

    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.addHandler(STDOUT_HANDLER)
    logger.setLevel(log_level)

    loggers[name] = logger

    return logger
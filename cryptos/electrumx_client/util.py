import logging

class LoggedClass(object):

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        self.log_prefix = ''
        self.throttled = 0

    def log_info(self, msg, throttle=False):
        # Prevent annoying log messages by throttling them if there
        # are too many in a short period
        if throttle:
            self.throttled += 1
            if self.throttled > 3:
                return
            if self.throttled == 3:
                msg += ' (throttling later logs)'
        self.logger.info(self.log_prefix + msg)

    def log_warning(self, msg):
        self.logger.warning(self.log_prefix + msg)

    def log_error(self, msg):
        self.logger.error(self.log_prefix + msg)
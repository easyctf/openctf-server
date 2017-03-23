from logging import Formatter
from logging.handlers import RotatingFileHandler


class CTFLogHandler(RotatingFileHandler):
    def __init__(self, path):
        RotatingFileHandler.__init__(self, path, maxBytes=10000, backupCount=1)

        formatter = Formatter("[%(asctime)s] %(message)s")
        self.setFormatter(formatter)

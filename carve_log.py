import logging

l = logging.getLogger()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ColorCodes:
    grey = "\x1b[38;21m"
    green = "\x1b[1;32m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    blue = "\x1b[1;34m"
    light_blue = "\x1b[1;36m"
    purple = "\x1b[1;35m"
    reset = "\x1b[0m"

class CustomFormatter(logging.Formatter):
    format_info = "[*]  %(message)s"
    format_error = "[!]  %(message)s"
    format_debug = "[-]  %(message)s"
    format_critical = "[#]  %(message)s"

    file_format_info = "[*]  %(asctime)s |\t%(levelname)s    \t| %(message)s"
    file_format_error = "[!]  %(asctime)s |\t%(levelname)s   \t| %(message)s"
    file_format_debug = "[-]  %(asctime)s |\t%(levelname)s   \t| %(message)s"
    file_format_critical = "[#]  %(asctime)s |\t%(levelname)s\t| %(message)s"

    FORMATS = {
        logging.DEBUG: ColorCodes.blue + format_debug + ColorCodes.reset,
        logging.INFO:  ColorCodes.green + format_info + ColorCodes.reset,
        logging.WARNING: bcolors.WARNING + format_info + ColorCodes.reset,
        logging.ERROR: ColorCodes.bold_red + format_error + ColorCodes.reset,
        logging.CRITICAL: bcolors.HEADER + format_critical + ColorCodes.reset,
    }
    FILE_FORMATS = {
        logging.DEBUG: file_format_debug, 
        logging.INFO:  file_format_info,
        logging.WARNING: file_format_info,
        logging.ERROR: file_format_error,
        logging.CRITICAL: file_format_critical
    }

    def __init__(self, to_file=False):
        self.to_file = to_file

    def format(self, record):
        if self.to_file:
            log_fmt = self.FILE_FORMATS.get(record.levelno)
        else:
            log_fmt = self.FORMATS.get(record.levelno)

        
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def logger_setup(verbose=False, quiet=False, log_file=None):
    """
    A function to set up logging based on the verbosity level.
    """
    if(verbose):
        l.setLevel(logging.DEBUG)

        # Console stream log handler 
        if not quiet:
            screen = logging.StreamHandler()
            screen.setLevel(logging.DEBUG)
            screen.setFormatter(CustomFormatter())
            l.addHandler(screen)

        # File stream log handler
        if log_file:
            debug_log = logging.FileHandler(log_file, encoding='utf-8')
            debug_log.setLevel(logging.DEBUG)
            debug_log.setFormatter(CustomFormatter(to_file=True))
            l.addHandler(debug_log)
       
        

    else:
        l.setLevel(logging.INFO)

        # Console stream log handler
        if not quiet:
            screen = logging.StreamHandler()
            screen.setLevel(logging.INFO)
            screen.setFormatter(CustomFormatter())
            l.addHandler(screen)

        # File stream log handler
        if log_file:
            debug_log = logging.FileHandler(log_file, encoding='utf-8')
            debug_log.setLevel(logging.INFO)
            debug_log.setFormatter(CustomFormatter(to_file=True))
            l.addHandler(debug_log)
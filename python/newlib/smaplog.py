
import sys
import os
import logging, logging.handlers

project_log = '/project/eecs/tinyos/corytestbed/local/var/log'

def start_log(emails=[], fileLevel=logging.INFO):
    logging.basicConfig(level=logging.DEBUG)

    if emails:
        mail_logger = logging.getLogger()
        mail = logging.handlers.SMTPHandler("localhost",
                                            "coryhall@eecs.berkeley.edu",
                                            emails,
                                            "[%s]" % sys.argv[0])
        mail.setLevel(logging.WARN)
        mail_logger.addHandler(mail)

    if os.access(project_log, os.W_OK):
        log = project_log
    elif os.access('/var/log/', os.W_OK):
        log = '/var/log'
    elif os.access('.', os.W_OK):
        log = '.'
    else:
        log = None

    print "Log:", log

    if log:
        # root messages
        logfile = '-'.join(sys.argv) + '.log'
        logfile = logfile.replace('/', '_')
        logfile = logfile.replace('.py', '')

        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        file_handler = logging.handlers.RotatingFileHandler(os.path.join(log, logfile), 'w', 50e6, 5)
        file_handler.setLevel(fileLevel)
        file_handler.setFormatter(formatter)

        logging.getLogger().addHandler(file_handler)

        # httpd logs
        logfile = '-'.join(sys.argv) + '_access.log'
        logfile = logfile.replace('/', '_')
        logfile = logfile.replace('.py', '')

        file_handler = logging.handlers.RotatingFileHandler(os.path.join(log, logfile), 'w', 50e6, 5)
        file_handler.setLevel(fileLevel)
        file_handler.setFormatter(formatter)

        logging.getLogger('HTTPD').addHandler(file_handler)
        logging.getLogger('HTTPD').propagate = False

        
    logging.info("Logging reinitialized: (%s) (%i)", (','.join(sys.argv)), os.getpid())

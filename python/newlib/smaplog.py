
import sys
import os
import logging, logging.handlers

project_log = '/project/eecs/tinyos/corytestbed/local/var/log'

def start_log(emails=[], screenLevel=logging.ERROR, fileLevel=logging.INFO):
    """Utility function for initializing the logging module in a
    useful way.  The default is to set the console loglevel to DEBUG
    and the file level to INFO.  WARN and above will be sent to the
    email list passed in.

    File logs are kept in either, /var/log or the current directory,
    in that order.  Apache-style HTTP logs are separated from other
    console messages, and both types use the RotatingFileHandler so
    that the disk doesn't fill up.

    It is recommended that you call this function before proceeding
    with using the sMAP library in order to capture any errors.
    """
    
    # Set root logger to see all messages
    logging.getLogger().setLevel(logging.DEBUG)

    # Configure messages that are shown on screen
    screen_handler = logging.StreamHandler(sys.stdout)
    screen_handler.setLevel(screenLevel)
    logging.getLogger().addHandler(screen_handler)

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
        #file_handler.setLevel(fileLevel)
        file_handler.setLevel(logging.DEBUG)
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

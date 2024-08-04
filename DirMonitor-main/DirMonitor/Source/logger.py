import logging
import config

# Configure logging for directory changes
directory_logging = logging.getLogger('directory')
directory_logging.setLevel(logging.INFO)
directory_handler = logging.FileHandler(config.LOG_FILE_DIRECTORY)
directory_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
directory_logging.addHandler(directory_handler)

# Configure logging for network activity
network_logging = logging.getLogger('network')
network_logging.setLevel(logging.INFO)
network_handler = logging.FileHandler(config.LOG_FILE_NETWORK)
network_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
network_logging.addHandler(network_handler)

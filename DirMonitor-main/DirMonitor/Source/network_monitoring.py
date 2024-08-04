import logging
from scapy.all import sniff

# Configure logging for network monitoring
network_logging = logging.getLogger('network')
network_logging.setLevel(logging.INFO)
network_handler = logging.FileHandler('network_activity.log')
network_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
network_logging.addHandler(network_handler)

def log_network_activity(packet, app):
    try:
        packet_info = str(packet.summary())
        network_logging.info(packet_info)
        app.update_network_output(packet_info)
    except Exception as e:
        network_logging.error(f"Error processing packet: {e}")

def start_network_monitoring(interface, app):
    try:
        sniff(iface=interface, prn=lambda p: log_network_activity(p, app), store=0)
    except Exception as e:
        network_logging.error(f"Error starting network monitoring: {e}")

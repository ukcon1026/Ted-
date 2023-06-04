from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from collections import defaultdict

log = core.getLogger()

# Threshold for rate limiting
THRESHOLD = 10

# Dictionary to keep track of packet counts per source IP
packet_counts = defaultdict(int)

def launch():
    core.addListenerByName("UpEvent", _handle_UpEvent)
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

def _handle_UpEvent(event):
    log.debug("POX is started")

def _handle_ConnectionUp(event):
    log.debug("POX connected with switch")

def _handle_PacketIn(event):
    packet = event.parsed
    if not packet.parsed:
        log.warning("Ignoring incomplete packet")
        return

    # Get source IP address from packet
    src_ip = packet.find('ipv4').srcip

    # Increment packet count for source IP
    packet_counts[src_ip] += 1

    # Check if packet count exceeds threshold
    if packet_counts[src_ip] > THRESHOLD:
        log.debug("Rate limiting packets from %s", src_ip)

        # Install rule to drop packets from source IP
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x0800 # Match on IPv4 packets
        msg.match.nw_src = src_ip
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
        event.connection.send(msg)
    else:
        log.debug("Flooding packet from %s", src_ip)

        # Flood packet out of all ports
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.data = event.ofp
        event.connection.send(msg)

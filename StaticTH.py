from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# Set the threshold for rate limiting (packets per second)
RATE_LIMIT_THRESHOLD = 100

# A dictionary to keep track of the packet counts for each source IP address
packet_counts = {}

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
    connection = event.connection

    # Check if the packet has an IP source address
    if packet.find('ipv4'):
        src_ip = packet.find('ipv4').srcip

        # Update the packet count for the source IP address
        if src_ip in packet_counts:
            packet_counts[src_ip] += 1
        else:
            packet_counts[src_ip] = 1

        # Check if the packet count exceeds the threshold
        if packet_counts[src_ip] > RATE_LIMIT_THRESHOLD:
            # If the threshold is exceeded, drop the packet
            drop_packet(connection, packet)
        else:
            # If the threshold is not exceeded, allow the packet to pass
            pass_packet(connection, packet)

def drop_packet(connection, packet):
    # Create an OpenFlow flow modification message to drop the packet
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    # You can set other parameters of the flow modification message as needed
    msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))  # Drop the packet

    # Send the flow modification message to the switch to drop the packet
    connection.send(msg)
    log.debug("Packet dropped")

def pass_packet(connection, packet):
    # Create an OpenFlow flow modification message to allow the packet to pass
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    # You can set other parameters of the flow modification message as needed
    msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))  # Forward the packet normally

    # Send the flow modification message to the switch to allow the packet to pass
    connection.send(msg)
    log.debug("Packet allowed to pass")


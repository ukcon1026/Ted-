from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

def launch():
    core.addListenerByName("UpEvent", _handle_UpEvent)
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

def _handle_UpEvent(event):
    log.debug("POX is started")

def _handle_ConnectionUp(evnet):
    log.debug("POX connected with switch")

def _handle_PacketIn(event):
    log.debug("Packet received from the port: %s", event.port)
    msg= of.ofp_flow_mod()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    event.connection.send(msg)

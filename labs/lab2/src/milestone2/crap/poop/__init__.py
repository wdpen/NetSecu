import playground

from .protocol_base import * 
from .client_protocol import PoopClientFactory, PoopClientProtocol
from .server_protocol import PoopServerFactory, PoopServerProtocol
from .packets import *


poopConnector = playground.Connector(protocolStack=(
    PoopClientFactory(),
    PoopServerFactory()))
playground.setConnector("poop", poopConnector)

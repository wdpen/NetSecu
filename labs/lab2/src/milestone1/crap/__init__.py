import playground
from .jack_crap import CrapClientFactory, CrapServerFactory
from .packets_crap import *

crapConnector = playground.Connector(protocolStack=(CrapClientFactory(),CrapServerFactory()))
playground.setConnector("crap", crapConnector)

import operator
from enum import Enum
from pyshark.packet.layers.xml_layer import XmlLayer


class IntEnum(Enum):
    def __cmp__(self, other):
        return self.value == other

    def __eq__(self, other):
        return self.value == other

    def __str__(self):
        return f"{self.name} ({self.value})"


class MessageType(IntEnum):
    RouteMonitoring = 0
    StatisticsReport = 1
    PeerDown = 2
    PeerUp = 3
    Initiation = 4
    Termination = 5


class PeerType(IntEnum):
    GlobalInstance = 0
    RDInstance = 1
    LocalInstance = 2
    LocRibInstance = 3


class BmpPacket:

    def __init__(self, capture_sequence: int, frame_sequence: int, frame: int, packet: XmlLayer):
        self.capture_sequence = capture_sequence
        self.frame_sequence = frame_sequence
        self.frame = frame
        self.packet = packet
        self.type = MessageType(int(self.packet.type))

    # transparent wrapper to avoid using packet.packet.attr
    def __getattr__(self, item):
        if item not in self.__dict__:
            return operator.attrgetter(item)(self.packet)
        else:
            return getattr(self, item)

import operator
from dataclasses import dataclass
from enum import Enum
from pyshark.packet.layers.xml_layer import XmlLayer


class IntEnum(Enum):

    def __cmp__(self, other):
        return self.value == other

    def __eq__(self, other):
        return self.value == other

    def __str__(self):
        return f"{self.name} ({self.value})"

    def __hash__(self):
        return hash((self.name, self.value))


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

    def __init__(self, capture_sequence: int, frame: int, frame_sequence: int, frame_bmp_count: int, packet: XmlLayer):
        self.capture_sequence = capture_sequence
        self.frame = frame
        self.frame_sequence = frame_sequence
        self.frame_bmp_count = frame_bmp_count
        self.packet = packet
        self.type = MessageType(int(self.packet.type))

    # transparent wrapper to avoid using packet.packet.attr
    def __getattr__(self, item):
        if item not in self.__dict__:
            try:
                return operator.attrgetter(item)(self.packet)
            except AttributeError:
                return None
        else:
            return getattr(self, item)

    # Print location of the packet to find easily in Wireshark
    # F = Frame, P = Packet
    def location_str(self) -> str:
        return f"@ (F{self.frame + 1}:P{self.frame_sequence + 1}/{self.frame_bmp_count})"


@dataclass(frozen=True, eq=True)
class PeerId:
    peer_type: PeerType
    peer_ip: str
    peer_rd: str

    @classmethod
    def from_packet(cls, packet: BmpPacket):
        peer_type = PeerType(int(packet.peer_type))
        peer_ip = packet.peer_ip_addr if "peer_ip_addr" in packet.field_names else packet.peer_ipv6_addr
        return PeerId(peer_type=peer_type, peer_ip=peer_ip, peer_rd=packet.peer_distinguisher)


class MonitoringType(IntEnum):
    AdjInPre = 0
    AdjInPost = 1
    AdjOutPre = (1 << 1)
    AdjOutPost = (1 << 1) + 1
    LocRib = (1 << 2)

    @classmethod
    def from_flags(cls, peer_type: PeerType, out: bool, post: bool):
        if peer_type == PeerType.LocRibInstance:
            if not out and not post:
                return MonitoringType.LocRib
            else:
                raise ValueError(f"LocRib Peer Type should not have out and/or post to True: out={out}, post={post}")
        else:
            return MonitoringType(((1 << 1) if out else 0) + (1 if post else 0))

    @classmethod
    def from_packet(cls, packet: BmpPacket):
        peer_type = PeerType(int(packet.peer_type))
        return MonitoringType.from_flags(peer_type=peer_type,
                                         out=bool(int(packet.peer_flags_adj_rib_out or "0")),
                                         post=bool(int(packet.peer_flags_post_policy or "0")))

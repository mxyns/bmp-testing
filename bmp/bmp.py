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


class BgpPduType(IntEnum):
    EoR = -1
    Withdraw = 0
    Update = 1


@dataclass()
class Nlri:
    prefix: str
    prefix_len: int
    prefix_id: int
    prefix_rd: str

    @classmethod
    def from_packet(cls, packet: BmpPacket):
        withdraw_len: int = int(packet.bgp_update_withdrawn_routes_length)
        update_len: int = int(packet.bgp_update_path_attributes_length)

        # unsupported mixed packet
        if withdraw_len != 0 and update_len != 0:
            raise ValueError("Mixed update and withdraw in BGP PDU not supported!")

        # packet is a EoR
        if withdraw_len == 0 and update_len == 0:
            return Nlri(prefix="EoR", prefix_len=0, prefix_rd="", prefix_id=0), BgpPduType.EoR

        # packet is a withdraw
        elif withdraw_len > 0 and update_len == 0:

            return Nlri(
                prefix=packet.bgp_withdrawn_prefix,
                prefix_len=int(packet.bgp_prefix_length),
                prefix_id=int(packet.bgp_nlri_path_id),
                prefix_rd=packet.bgp_rd,
            ), BgpPduType.Withdraw

        # packet is an update
        elif withdraw_len == 0 and update_len > 0:
            if int(type_code := packet.bgp_update_path_attribute_type_code) == 1:
                return Nlri(
                    prefix=packet.bgp_nlri_prefix,
                    prefix_len=int(packet.bgp_prefix_length),
                    prefix_rd=packet.bgp_rd,
                    prefix_id=int(packet.bgp_nlri_path_id or 0),
                ), BgpPduType.Update

            elif int(type_code) == 14:  # MP_REACH
                prefix = packet.bgp_nlri_prefix or \
                         packet.bgp_mp_reach_nlri_ipv6_prefix or \
                         packet.bgp_mp_reach_nlri_ipv4_prefix

                prefix_len = int(packet.bgp_prefix_length or prefix.split("/")[-1])
                prefix_id = int(packet.bgp_nlri_path_id or 0)
                prefix_rd = packet.bgp_rd or ""

                return Nlri(
                    prefix=prefix,
                    prefix_len=prefix_len,
                    prefix_id=prefix_id,
                    prefix_rd=prefix_rd
                ), BgpPduType.Update

            elif int(type_code) == 15:  # MP_UNREACH
                prefix = packet.bgp_nlri_prefix or \
                         packet.bgp_mp_unreach_nlri_ipv6_prefix or \
                         packet.bgp_mp_unreach_nlri_ipv4_prefix

                if prefix is None:  # EoR
                    return Nlri(prefix="EoR", prefix_len=0, prefix_id=0, prefix_rd=""), BgpPduType.EoR

                return Nlri(
                    prefix=prefix.split("/")[0],
                    prefix_len=int(packet.bgp_prefix_length or prefix.split("/")[-1]),
                    prefix_rd=packet.bgp_rd,
                    prefix_id=int(packet.bgp_nlri_path_id or 0),
                ), BgpPduType.Withdraw
            else:
                raise ValueError("Type code not supported!")
        else:
            raise ValueError("Should be unreachable!")


class BmpPacketRouteMonitoring(BmpPacket):
    bgp_nlri: Nlri
    bgp_pdu_type: BgpPduType

    def __init__(self, capture_sequence: int, frame: int, frame_sequence: int, frame_bmp_count: int, packet: XmlLayer):
        super().__init__(capture_sequence=capture_sequence, frame_sequence=frame_sequence, frame=frame,
                         packet=packet, frame_bmp_count=frame_bmp_count)


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

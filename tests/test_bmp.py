import json
import unittest

import pyshark

import tests.common as common
from bmp import bmp
from bmp.bmp import BmpPacket, Nlri, BgpPduType


class BMP(unittest.TestCase):
    file_path: str = None
    pcap: pyshark.FileCapture = None
    bmp: list[BmpPacket] = None

    # print test name before running each
    def setUp(self) -> None:
        common.print_test_header(self)

    @classmethod
    def setUpClass(cls) -> None:
        cls.file_path = common.PCAP_PATH
        cls.pcap = pyshark.FileCapture(common.PCAP_PATH, tshark_path=common.TSHARK_PATH,
                                       decode_as={f"tcp.port=={common.BMP_PORT}": "bmp"},
                                       custom_parameters=common.TSHARK_ARGS)
        print(f"Running TShark {cls.pcap._get_tshark_version()} from {cls.pcap._get_tshark_path()}")
        cls.bmp = list()

        seq = 0
        for frame_id, frame in enumerate(cls.pcap):
            if (packets := frame.get_multiple_layers("bmp")) is not None and len(packets) > 0:
                for frame_seq, packet in enumerate(packets):
                    cls.bmp.append(
                        BmpPacket(capture_sequence=seq, frame=frame_id, frame_sequence=frame_seq,
                                  frame_bmp_count=len(packets), packet=packet))
                    seq += 1

        print("=== SETUP LOGS ====")
        print(f"BMP Packet count: {seq}")
        # this is disgustingly inefficient
        types: dict[bmp.MessageType, int] = {
            msg_type.name: len(list(filter(lambda bmp_packet: int(bmp_packet.packet.type) == msg_type, cls.bmp))) for
            msg_type in bmp.MessageType}
        print(types)
        print("=== SETUP LOGS ====")

        print("=== TEST LOGS ====")

    # ensure that preprocessing didn't duplicate packets
    def test_indices(self) -> None:
        # check if list is going from 0 to len(lst) monotonically, incr of 1
        def _assert_monotone(lst: list):
            self.assertEqual(len(set(lst)), len(lst))
            self.assertListEqual(list(range(len(lst))), lst)

        capture_sequences = list(map(lambda p: p.capture_sequence, self.bmp))
        _assert_monotone(capture_sequences)

    # ensure that the bmp version is the same for the same sessions
    def test_version(self) -> None:

        fail = False
        sessions = dict()
        for packet in self.bmp:
            if packet.type == bmp.MessageType.Initiation:
                frame = self.pcap[packet.frame]
                session_id = (frame.ip.dst, frame.ip.src, frame.tcp.port, frame.tcp.dstport)
                bmp_version = int(packet.version)
                if sessions.get(session_id) is None:
                    sessions[session_id] = (packet.capture_sequence, bmp_version)

                # if version changed
                if sessions[session_id][1] != bmp_version:
                    print(
                        f"Version changed from {sessions[session_id][1]} to {bmp_version} on session {str(session_id)}")
                    fail = True

        self.assertFalse(fail)

    # summarize peer up/down state and count ignored messages (received before peer up / after peer down)
    def test_peerup(self) -> None:

        # peer stores
        # peer ids as key are dataclasses of (Type: bmp.PeerType, IP: str, RD: str) from module bmp
        # values are dicts with id, type, state, stats etc.
        peers: dict[
            bmp.PeerId,
            dict[str, any]
        ] = dict()

        vrfs: dict[
            bmp.PeerId,
            dict[str, any]
        ] = dict()

        # get a peer from one of the local peer stores
        def _get_peer(peer_id: bmp.PeerId):
            store = vrfs if peer_id.peer_type == bmp.PeerType.LocRibInstance else peers
            return store.setdefault(peer_id, {
                "id": peer_id,
                "type": peer_id.peer_type,
                "type_name": peer_id.peer_type.name,
                "state": None,
                "state_msgs": list(),
                "stats": dict()
            })

        # increment a stat for a peer, create it if missing
        def _incr_stat(peer, stat_name: str):
            peer["stats"][stat_name] = peer["stats"].setdefault(stat_name, 0) + 1

        print("====== TIMELINE ======")
        # play the bmp pcap
        for packet in self.bmp:

            # if a state message this is a new peer state
            packet_type = packet.type

            # ignore initiation messages, has no per-peer header
            if packet_type in [bmp.MessageType.Initiation, bmp.MessageType.Termination]:
                continue

            peer_id = bmp.PeerId.from_packet(packet=packet)
            peer = _get_peer(peer_id)
            peer_state = peer["state"]

            # got a peer state message, update peer state
            if packet_type in [bmp.MessageType.PeerUp, bmp.MessageType.PeerDown]:
                if peer_state == packet_type:
                    _incr_stat(peer, f"{packet_type.name}_duplicate")
                    print(f"peer {peer_id} duplicate state {peer_state} {packet.location_str()}")
                else:
                    peer["state_msgs"].append(packet.capture_sequence)
                    peer["state"] = packet_type
                    _incr_stat(peer, packet_type.name)
                    print(f"{peer['type_name']} {peer_id} changed state {peer_state} -> {packet_type}")

            # got any other message
            else:
                not_up = peer_state != bmp.MessageType.PeerUp
                _incr_stat(peer, f"{packet_type.name}_ignored" if not_up else packet_type.name)

        print("====== TIMELINE ======\n"
              "====== SUMMARY PRETTY ======")

        def _pretty_print_peer(peer_id: bmp.PeerId, peer_data: dict[str, any]):
            print(f"Peer: Type={peer_id.peer_type} IP={peer_id.peer_ip} RD={peer_id.peer_rd}")
            print(json.dumps(peer_data, default=str, indent=4))

        for peer_id, peer_data in peers.items():
            _pretty_print_peer(peer_id, peer_data)

        print("====== SUMMARY PRETTY ======\n"
              "====== SUMMARY RAW ======")
        print(peers)
        print(vrfs)
        print("====== SUMMARY RAW ======")

    # ensure that the peer type is never 0 when the peer RD is not zero and vice-versa
    def test_peer_type(self) -> None:

        fail = False
        for packet in self.bmp:
            if not all(field in packet.field_names for field in ["peer_type", "peer_distinguisher"]):
                continue

            can_rd = int(packet.peer_type) != bmp.PeerType.GlobalInstance
            need_rd = int(packet.peer_type) in [bmp.PeerType.RDInstance, bmp.PeerType.LocalInstance]
            has_rd = packet.peer_distinguisher != "00:00:00:00:00:00:00:00"
            if (has_rd and not can_rd) or (need_rd and not has_rd):
                print(f"Packet {packet.capture_sequence} {packet.location_str()}"
                      f"has invalid type / rd combination")
                print(f"Message type: {packet.type}, "
                      f"peer type: {packet.packet.peer_type}. "
                      f"out: {packet.packet.peer_flags_adj_rib_out}, "
                      f"post: {packet.packet.peer_flags_post_policy}")
                fail = True

        self.assertFalse(fail)

    # TODO move NLRI code to BmpPacket
    def test_monitoring_summary(self):

        peers: dict[bmp.PeerId, dict[str, any]] = dict()

        def _get_peer(peer_id: bmp.PeerId):
            return peers.setdefault(peer_id, {
                "id": peer_id,
            } | {str(mon_type): dict() for mon_type in bmp.MonitoringType})

        def _update_rib(rib: dict[str, dict[str, any]], packet: bmp.BmpPacket) -> None:

            def _get_prefix(nlri: Nlri) -> dict[str, any]:
                prefix = f"{nlri.prefix}/{nlri.prefix_len}, id={nlri.prefix_id}, rd=n{nlri.prefix_rd}"
                return rib.setdefault(prefix, {
                    # immutable
                    "prefix": prefix,
                    "prefix_len": nlri.prefix_len,
                    "id": nlri.prefix_id,
                    "rd": nlri.prefix_rd,
                    # mutable
                    "update_count": 0,
                    "withdraw_count": 0,
                    "duplicate_withdraw_count": 0,
                    "last": None,  # 0 is withdrawn, 1 is updated
                    "last_attr": None,  # current attributes if last is 1
                    "timeline": list(),  # list of (capture_sequence, pdu_type) from packets affecting the prefix
                })

            nlri, pdu_type = Nlri.from_packet(packet=packet)
            prefix_info = _get_prefix(nlri=nlri)

            prefix_info["timeline"] += [(packet.capture_sequence, pdu_type)]

            match pdu_type:
                case BgpPduType.EoR:
                    prefix_info["update_count"] += 1

                case BgpPduType.Withdraw:
                    prefix_info["duplicate_withdraw_count"] += 1 if prefix_info["last"] in [0, None] else 0
                    prefix_info["withdraw_count"] += 1
                    prefix_info["last"] = 0
                    prefix_info["last_attr"] = None

                case BgpPduType.Update:
                    prefix_info["update_count"] += 1
                    prefix_info["last"] = 1
                    prefix_info["last_attr"]: dict[str, any] = {
                        k.replace("bgp_update_path_attribute_", ""): getattr(packet, k, None) for k in
                        packet.field_names if
                        k.startswith("bgp_update_path_attribute")
                    }

        for packet in self.bmp:
            if packet.type != bmp.MessageType.RouteMonitoring:
                continue

            peer_id = bmp.PeerId.from_packet(packet=packet)
            mon_type = bmp.MonitoringType.from_packet(packet=packet)
            peer = _get_peer(peer_id=peer_id)
            rib = peer[str(mon_type)]
            _update_rib(rib=rib, packet=packet)

        print(json.dumps({str(k): v for k, v in peers.items()}, indent=2, default=str))

    # TODO check statistics (correct type and count, counters always going up etc.)
    # TODO check peer flags correspond to peer type (only one in loc-rib, etc)
    # print test name after running each
    def tearDown(self) -> None:
        common.print_test_header(self)

    # ran at the end of the test suite
    @classmethod
    def tearDownClass(cls) -> None:
        print("==== TEST LOGS ====")


if __name__ == '__main__':
    unittest.main()

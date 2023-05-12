import unittest

import pyshark

import tests.common as common
from bmp import bmp
from bmp.bmp import BmpPacket


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
                                       decode_as={f"tcp.port=={common.BMP_PORT}": "bmp"})
        print(f"Running TShark {cls.pcap._get_tshark_version()} from {cls.pcap._get_tshark_path()}")
        cls.bmp = list()

        seq = 0
        for frame_id, frame in enumerate(cls.pcap):
            if (packets := frame.get_multiple_layers("bmp")) is not None and len(packets) > 0:
                for frame_seq, packet in enumerate(packets):
                    cls.bmp.append(
                        BmpPacket(capture_sequence=seq, frame_sequence=frame_seq, frame=frame_id, packet=packet))
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
            self.assertEquals(len(set(lst)), len(lst))
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
        # peer ids as key are tuple of (IP, RD, Type)
        # values are dicts with id, type, state, stats etc.
        peers: dict[
            tuple[str, str, int],
            dict[str, any]
        ] = dict()

        vrfs: dict[
            tuple[str, str, int],
            dict[str, any]
        ] = dict()

        # get a peer from one of the local peer stores
        def _get_peer(peer_type: bmp.PeerType, peer_id):
            store = vrfs if peer_type == bmp.PeerType.LocRibInstance else peers
            return store.setdefault(peer_id, {
                "id": peer_id,
                "type": peer_type,
                "type_name": peer_type.name,
                "state": None,
                "state_msgs": list(),
                "stats": dict()
            })

        # increment a stat for a peer, create it if missing
        def _incr_stat(peer, stat_name: str):
            peer["stats"][stat_name] = peer["stats"].setdefault(stat_name, 0) + 1

        # play the bmp pcap
        for packet in self.bmp:

            # if a state message this is a new peer state
            packet_type = packet.type

            # ignore initiation messages, not per-peer header
            if packet_type == bmp.MessageType.Initiation:
                continue

            peer_type = bmp.PeerType(int(packet.peer_type))
            peer_ip = packet.peer_ip_addr if "peer_ip_addr" in packet.field_names else packet.peer_ipv6_addr
            peer_id = (peer_ip, packet.peer_distinguisher, peer_type.value)
            peer = _get_peer(peer_type, peer_id)
            peer_state = peer["state"]

            # got a peer state message, update peer state
            if packet_type in [bmp.MessageType.PeerUp, bmp.MessageType.PeerDown]:
                if peer_state == packet_type:
                    _incr_stat(peer, f"{packet_type.name}_duplicate")
                    print(f"peer {peer_id} duplicate state {peer_state}")
                else:
                    peer["state_msgs"].append(packet.capture_sequence)
                    peer["state"] = packet_type
                    _incr_stat(peer, packet_type.name)
                    print(f"{peer['type_name']} {peer_id} changed state {peer_state} -> {packet_type}")

            # got any other message
            else:
                not_up = peer_state != bmp.MessageType.PeerUp
                _incr_stat(peer, f"{packet_type.name}_ignored" if not_up else packet_type.name)

        # TODO pretty print the summary router-like
        print(peers)
        print(vrfs)

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
                print(f"Packet {packet.capture_sequence} in frame {packet.frame + 1} at "
                      f"{packet.frame_sequence}/{len(self.pcap[packet.frame].get_multiple_layers('bmp'))} "
                      f"has invalid type / rd combination")
                print(f"Message type: {packet.type}, "
                      f"peer type: {packet.packet.peer_type}. "
                      f"out: {packet.packet.peer_flags_adj_rib_out}, "
                      f"post: {packet.packet.peer_flags_post_policy}")
                fail = True

        self.assertFalse(fail)

    # TODO summary of received message for each type of monitoring (in - loc - out) with prefix and peer address

    # print test name after running each
    def tearDown(self) -> None:
        common.print_test_header(self)

    # ran at the end of the test suite
    @classmethod
    def tearDownClass(cls) -> None:
        print("==== TEST LOGS ====")


if __name__ == '__main__':
    unittest.main()

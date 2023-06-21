import os
import unittest
import json

BMP_PORT = os.environ.get("BMP_PORT") or 12345
PCAP_PATH = os.environ.get("PCAP_PATH") or "~/frr-ribout-testing-20230517_1602.pcap"
PCAP_PATH = PCAP_PATH if "~/" not in PCAP_PATH else os.path.expanduser(PCAP_PATH)

TSHARK_PATH = os.environ.get("TSHARK_PATH") or "/usr/local/bin/"
TSHARK_PATH = TSHARK_PATH if "~/" not in TSHARK_PATH else os.path.expanduser(TSHARK_PATH)

TSHARK_ARGS = json.loads(os.environ.get("TSHARK_ARGS") or "[]") or []

print(f"""
==== ENV =====
TSHARK_PATH = {TSHARK_PATH}
TSHARK_ARGS = {TSHARK_ARGS}
TESTDATA_FILENAME = {PCAP_PATH}
BMP_PORT = {BMP_PORT}
==== ENV =====
""")


def print_test_header(test: unittest.TestCase):
    print("=====", test._testMethodName, "=====")

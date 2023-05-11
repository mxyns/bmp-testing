import os
import unittest

BMP_PORT = os.environ.get("BMP_PORT") or 12345
PCAP_PATH = os.environ.get("PCAP_PATH") or "~/frr-ribout-testing-20230511_1048.pcap"
TSHARK_PATH = os.environ.get("TSHARK_PATH") or "/usr/local/bin/"

print(f"""
==== ENV =====
TSHARK_PATH = {TSHARK_PATH}
TESTDATA_FILENAME = {PCAP_PATH}
BMP_PORT = {BMP_PORT}
==== ENV =====
""")


def print_test_header(test: unittest.TestCase):
    print("=====", test._testMethodName, "=====")

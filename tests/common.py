import os
import unittest

PCAP_PATH = os.environ.get("PCAP_PATH") or "~/frr-ribout-testing-20230511_1048.pcap"
TSHARK_PATH = os.environ.get("TSHARK_PATH") or "/usr/local/bin/"

print(f"""
==== ENV =====
TSHARK_PATH = {TSHARK_PATH}
TESTDATA_FILENAME = {PCAP_PATH}
==== ENV =====
""")


def print_test_header(test: unittest.TestCase):
    print("=====", test._testMethodName, "=====")

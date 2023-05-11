import argparse
import os
import subprocess
import sys

DEFAULT_BMP_PORT = 12345

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('pcap', type=argparse.FileType('r'), help='pcap file to read')
    parser.add_argument('-t', '--tshark', type=argparse.FileType('r'),
                        help='path to tshark executable used')
    parser.add_argument('-p', '--port', type=int,
                        help="tcp port for BMP (overrides the user's currently set preference in Wireshark)",
                        default=DEFAULT_BMP_PORT)
    parser.add_argument('unittest_args', nargs='*')

    args = parser.parse_args()

    # Now set the sys.argv to the unittest_args (leaving sys.argv[0] alone)
    sys.argv[1:] = args.unittest_args

    print(sys.argv)

    custom_env = {
        **os.environ,
        "TSHARK_PATH": getattr(args.tshark, "name", ""),
        "PCAP_PATH": getattr(args.pcap, "name", ""),
        "BMP_PORT": str(getattr(args, "port", DEFAULT_BMP_PORT))
    }
    subprocess.call([sys.executable, '-m', 'unittest', *args.unittest_args], env=custom_env)

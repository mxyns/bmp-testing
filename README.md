# bmp-testing

Collection of Python tests to run on a .pcap which checks aspects of a BMP implementation

## Supported tests

### Assert tests

- [x] Ensure pre-processing was safe : `test_indices`
- [x] Version is always the same a session : `test_version`
- [x] Ensure correct Peer Type and Peer Distinguisher : `test_peer_type`
- [x] Statistics Counters always going up : `test_stats`

### Informative tests

- [x] Summarize peer states, count duplicates : `test_peerup`
- [x] Summarize updates and withdraws for each monitoring type and prefix : `test_monitoring_type`
- [x] Final RIB state for each peer : `test_monitoring_type`

## Dependencies

Using Python 3.10.6+ (and a RECOMMENDED venv)

`python -m pip install -r requirements.txt`

## Running

This project uses a script called `run_tests.py`
to run the Python `unittest` module with user arguments

### Basic run

`python run_tests.py`

### Arguments

| argument                   | type                | description                   | example                                                                        |
|----------------------------|---------------------|-------------------------------|--------------------------------------------------------------------------------|
| `-t`<br/>`--tshark`        | optional, path      | tshark executable             | `python run_tests.py -t /path/to/tshark /path/to/pcap`                         |
| `-ta`<br/>`--tsharkargs`   | optional, N * str   | tshark arguments              | `python run_tests.py -ta "-d tcp.port==1790,bmp" "other arg" -- /path/to/pcap` |
| `-p`<br/>`--port`          | optional, int       | bmp port for tshark           | `python run_tests.py -p 1790 /path/to/pcap`                                    |
| -------------------------- | ------------------- | ----------------------------- | ---------------------------------------------------------------                |
| `--`                       |                     | begin positional arguments    | `python run_tests.py <opt-args> -- <pos-args>`                                 |
| pcap                       | positional, path    | .pcap input file              | `python run_tests.py <opt-args> -- /path/to/pcap`                              |
| unittest_args              | positional, N * str | arguments for unittest        | `python run_tests.py <opt-args> -- <pcap> -k BMP`                              |

### Subset of tests

Use the `-k <expr>` parameter in the `unittest_args` parameter ([Arguments](#arguments))

`<expr>` can be anything that matches a module, file, test suite or test

Example:

| type       | example<br/>name    | example<br/>location |
|------------|---------------------|----------------------|
| file path  | `tests/test_bmp.py` | `tests`              |
| class name | `BMP`               | `tests/test_bmp.py`  |
| test name  | `test_peerup`       | `tests/test_bmp.py`  |

### Isolating the tests' logs

The `unittest` Python module adds logs on top of the prints used by the test cases.
To remove them redirect stderr using `2> /dev/null` or `2> nul`

### Manual Run

Running the tests without the `run_tests.py` script is also possible.
This script sets environment variable using the parsed user's arguments.
It then calls the module using `python -m unittest <remaining-args>`.
Setting the environment variables manually and running the command yourself works too.
See `run_tests.py` and `tests/common.py` for the relevant environment variable names. 

# bmp-testing

Collection of Python tests to run on a .pcap which checks aspects of a BMP implementation

## Supported tests

### Assert tests
- [x] Ensure pre-processing was safe : `test_indices`
- [x] Version is always the same a session : `test_version`
- [x] Ensure correct Peer Type and Peer Distinguisher : `test_peer_type`

### Informative tests
- [x] Summarize peer states, count duplicates : `test_peerup`
- [ ] Summarize updates and withdraws for each monitoring type and prefix
- [ ] (Final RIB state for each peer?)

## Dependencies

Using Python 3.10.6+ (and a RECOMMENDED venv)

`python -m pip install -r requirements.txt`

## Running

This project uses a script called `run_tests.py`
to run the Python `unittest` module with user arguments

### Basic run

`python run_tests.py`

### Arguments

| argument            | type       | description                  | example                                                |
|---------------------|------------|------------------------------|--------------------------------------------------------|
| pcap                | positional | specify .pcap input file     | `python run_tests.py /path/to/pcap`                    |
| `-t`<br/>`--tshark` | optional   | specify tshark executable    | `python run_tests.py /path/to/pcap -t /path/to/tshark` |
| `--`                |            | pass arguments to `unittest` | `python run_tests.py <args> -- -k <expr>`              |

### Subset of tests

`python run_tests.py <args> -- -k <expr>`

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

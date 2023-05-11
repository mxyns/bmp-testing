# bmp-testing

Collection of Python tests to run on a .pcap which checks aspects of a BMP implementation

## Dependencies

Using Python 3.10.6+ (and a RECOMMENDED venv)

`python -m pip install -r requirements.txt`

## Running

### All tests

`python -m unittest`

### Subset of tests

`python -m unittest -k <expr>`

`<expr>` can be anything that matches a module, file, test suite or test

Example:

| type       | example<br/>name    | example<br/>location |
|------------|---------------------|----------------------|
| file path  | `tests/test_bmp.py` | `tests`              |
| class name | `BMP`               | `tests/test_bmp.py`  |
| test name  | `test_peerup`       | `tests/test_bmp.py`  |

# Setup & Environment

Ensure Python and necessary libraries are installed. Libaries can be fetched with:
```
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

To see the results of Task 1, run:
`python3 baseline_ctr.py`

To see the results of Task 2, run:
`python3 handshake.py`

To see the results of Task 3, run:
`python3 secure_record.py`

To see the results of any test in Task 4, run:
`python3 tests/testX.py`, where X is the desired test number.

The shared communication structure for the tests can be found in
`tests/session.py`
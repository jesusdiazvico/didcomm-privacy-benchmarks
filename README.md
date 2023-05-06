# Setting up
@TODO: Configure a dockerfile or something to automate this.

1. Set up a python virtualenv
2. Install didcomm and numpy

# Printing results

## authcrypt(m)

To get stats for the conventional authcrypt mode, run:

`$ ./get-stats.sh <iters> <output_file>`
`$ gnuplot print-stats.gp`

The raw data will appear in `<output_file>`, with the corresponding graph will be in the file "output.png"

## Naive anoncrypt(authcrypt(m))

To get the stats for the naive anoncrypt(authcrypt(m)) mode:

Replace the file "./venv/lib/python3.10/site-packages/didcomm/pack_encrypted.py" with the file "./pack_encrypted.py", and then do as for the conventional authcrypt mode.

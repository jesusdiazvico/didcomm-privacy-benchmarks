# About This Repository

This repository includes code used in the paper "What DIDComm Out of It? 
Analysis and Improvements of DIDComm Messaging" to run some benchmarks.

The code outputs the CPU time needed for encryption and decryption in
different modes of operation in DIDComm, as well as the sizes of the
resutling DIDComm messages.

The analysed modes include the following *existing modes*:
- `anon`: DIDComm's basic anoncrypt mode. Builds a sender-anonymous, 
confidential, and unauthenticated channel between one sender and `n` recipients.
- `auth`: DIDComm's basic authcrypt mode. Builds a confidential and
sender-authenticated channel between one sender and `n` recipients.
- `naive-a-auth`: The naive way to combine `anon` and `auth`. This runs
first `auth`, serializes the result, and runs `anon` on it. The sender 
is authenticated, but no external observer learns its identity.

We also analyze the following proposed improvements:
- `merge-a-auth`: Achieves the same goal as  `naive-a-auth`, but more
efficiently.
- `ra-anon`: Adds receiver anonymity on top of `anon`. That is, the resulting
DIDComm messages do not leak the identity of the recipients.
- `ra-a-auth`: Combines `merge-a-auth` and `ra-anon`. That is, builds a 
sender-anonymous and receiver-anonymous confidential channel, with sender
authentication.

# Requirements

The code is in Python3. All needed packages are listed in the `requirements.txt`
file. If you have a working Python3 implementation, you only need to run:

```
pip install -r requirements.txt
```

And you are all done. Ideally, you should do that in a virtual environment, 
though, to avoid poluting  your global Python3 environment. 

There are also a set of utility scripts in Bash and for Gnuplot. These work
in Ubuntu. Probably also in other UNIX-based systems.

# Running the programs, individually

Once you have the environment readym you can run the following commands to get
the data/plots:

```
$ python3 [program] <msg> <num. recipients> <iters>
```

Where `[program]` must be either `anon.py`, `auth.py`, `naive-a-auth.py`, 
`merge-a-auth.py`, `ra-anon.py`, or `ra-a-auth.py`. The parameters description
is as follows:

- `<msg>`: The message you want to encrypt (no blank spaces).
- `<num. recipients>`: A number larger than or equal to `1`. The message will be
encrypted towards at most that many recipients. First using `1` recipient, then
`2`, and so on until `<num. recipients>`.
- `<iters>`: The number of times you want to run the encryption-decryption 
cycle.

The previous programs then encrypt and decrypt the specified message, as many 
times as indicated. First for 

CPU time is measured for encryption and decryption, as well
as DIDComm message sizes, and some stats are printed to the standard output.
Concretely, the programs spit out Gnuplot-compatible tables, as follows:

```
# Header: This tells you what the program produced
<recipients>\t<avg. enc time>\t<stdev. enc time>\t<avg. dec time>\t<stdev dec time>\t<avg. size>\t<stdev size>
```

Where, excluding the header, there are `<num. recipients>` rows with the format
given above. The columns are as follows:

- `recipients`: The number of recipients used to obtain the statistics in the 
current row.
- `avg. enc time`: The mean CPU encryption time computed for the given `<iters>`
number of iterations,.
- `stdev enc time`: The standard deviation for CPU encryption time.
- `avg. dec time`: The mean CPU decryption time.
- `stdev dec time`: The standard deviation for the CPU decryption time.
- `avg. size`: The mean size of the produced DIDComm messages.
- `stdev size`: The standard deviation for DIDComm messages.

If you redirect the output to some file, Gnuplot can read it. The scripts ending
`.gp` are Gnuplot scripts ready to do that for you. For instance, if you run

```
python3 anon.py Hello 3 1000 > results.anon
gnuplot print-stats-enc-cpu.gp  # This expects a file named "results.anon"
```

You will get a PNG file named "results-enc.png" with a graphical depiction of 
the data in "results.anon".

## I'm a bit lazy, is there some faster way to get the data?

Sure. If you run:

```
$ ./get-stats <mode> <niters> <output file>
```

Where `<mode>` is one of `[anon,auth,naive-a-auth,merge-a-auth,ra-anon,ra-a-auth]`, 
you get the data corresponding to CPU enc time, CPU dec time, and message size 
results over `<niters>` iterations, for the given mode, in the file you specified.
Then you can run the Gnuplot scripts over those (but beware that the Gnuplot
scripts expect concrete file names!)

## Just give me the ~~data~~ plots!

Ok. Then, run:

```
$ ./get-all-stats-and-print
```

This will run all modes, for `1000` iterations, to encrypt the message "Hello", 
and will plot the results in three .png files:

- `results-enc.png` for CPU encryption times.
- `results-dec.png` for CPU decryption times.
- `results-size.png` for DIDComm message sizes.

## Nah, this is too much I don't even want to install Python

Do not despair! If you have a local Docker installation, just run:

```
$ docker run -p 5000:5000 jdiazvico/didcomm-benchmarks
```

Then, you can comfortably access `localhost:5000` from your preferred browser,
and that should show you some pre-computed graphs.

If you want to recompute them locally, run the following instead:

```
$ docker run -p 5000:5000 jdiazvico/didcomm-benchmarks ./get-all-stats-print-and-post.sh
```

This takes some more time to load, but you will get some freshly computed stats
using the code in this repo. Note that this will require time proportional to 
the resources you allocate to your running Docker container.

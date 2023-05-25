#!/bin/bash

bash get-stats.sh anon 1000 results.anon
bash get-stats.sh auth 1000 results.auth
bash get-stats.sh naive-a-auth 1000 results.naive-a-auth
bash get-stats.sh merge-a-auth 1000 results.merge-a-auth
bash get-stats.sh ra-anon 1000 results.ra-anon
bash get-stats.sh ra-a-auth 1000 results.ra-a-auth
gnuplot print-stats-enc-cpu.gp
gnuplot print-stats-dec-cpu.gp
gnuplot print-stats-size.gp

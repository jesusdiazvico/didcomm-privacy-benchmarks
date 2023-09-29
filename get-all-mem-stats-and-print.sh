#!/bin/bash

echo "Getting stats for all modes."
bash get-mem-stats.sh anon 1000 results-mem.anon
bash get-mem-stats.sh auth 1000 results-mem.auth
bash get-mem-stats.sh naive-a-auth 1000 results-mem.naive-a-auth
bash get-mem-stats.sh merge-a-auth 1000 results-mem.merge-a-auth
bash get-mem-stats.sh ra-anon 1000 results-mem.ra-anon
bash get-mem-stats.sh ra-a-auth 1000 results-mem.ra-a-auth

echo "Plotting reuslts."
gnuplot print-stats-mem-cpu.gp

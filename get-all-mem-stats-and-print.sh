#!/bin/bash

echo "Getting stats for all modes."
echo "Getting stats for anon."
bash get-mem-stats.sh anon 1000 results-mem.anon
echo "Getting stats for auth."
bash get-mem-stats.sh auth 1000 results-mem.auth
echo "Getting stats for naive-a-auth."
bash get-mem-stats.sh naive-a-auth 1000 results-mem.naive-a-auth
echo "Getting stats for merge-a-auth."
bash get-mem-stats.sh merge-a-auth 1000 results-mem.merge-a-auth
echo "Getting stats for ra-anon."
bash get-mem-stats.sh ra-anon 1000 results-mem.ra-anon
echo "Getting stats for ra-a-auth."
bash get-mem-stats.sh ra-a-auth 1000 results-mem.ra-a-auth

echo "Plotting reuslts."
gnuplot print-stats-mem.gp

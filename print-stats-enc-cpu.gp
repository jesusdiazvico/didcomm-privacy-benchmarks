set terminal png size 800,800
set output 'results-enc.png'
set xlabel "Number of recipients"
set ylabel "Enc CPU time (s)"
set xtics 1
plot \
"results.anon" u 1:2:3 with errorlines lw 2 pt 1 linecolor rgb "red" title "anon", \
"results.auth" u 1:2:3 with errorlines lw 2 pt 2 linecolor rgb "blue" title "auth", \
"results.naiveaa" u 1:2:3 with errorlines lw 2 pt 3 linecolor rgb "green" title "naive-anon-auth", \
"results.mergeaa" u 1:2:3 with errorlines lw 2 pt 4 linecolor rgb "orange" title "merge-anon-auth", \
"results.raa" u 1:2:3 with errorlines lw 2 pt 5 linecolor rgb "black" title "recv-anon", \
"results.raauth" u 1:2:3 with errorlines lw 2 pt 6 linecolor rgb "purple" title "ra-a-auth"

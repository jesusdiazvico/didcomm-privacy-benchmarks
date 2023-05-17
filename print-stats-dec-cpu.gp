set terminal png size 800,800
set output 'results-dec.png'
set xlabel "Number of recipients"
set ylabel "Dec CPU time (s)"
set xtics 1
plot \
"results.anon" u 1:4:5 with errorlines lw 2 pt 1 linecolor rgb "red" title "anon(m)", \
"results.auth" u 1:4:5 with errorlines lw 2 pt 2 linecolor rgb "blue" title "auth(m)", \
"results.naiveaa" u 1:4:5 with errorlines lw 2 pt 3 linecolor rgb "green" title "naive-anon(auth(m))", \
"results.raa" u 1:4:5 with errorlines lw 2 pt 4 linecolor rgb "black" title "recv-anon(m)"

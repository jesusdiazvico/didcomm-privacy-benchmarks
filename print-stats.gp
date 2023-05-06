set terminal png size 800,800
set output 'results.png'
set xlabel "Number of recipients"
set ylabel "CPU time (s)"
set xtics 1
plot "results.authcrypt" u 1:2:3 with errorlines lw 2 pt 2 linecolor rgb "red" title "auth(m)", \
"results.naiveaa" u 1:2:3 with errorlines lw 2 pt 4 linecolor rgb "blue" title "naive anon(auth(m))"

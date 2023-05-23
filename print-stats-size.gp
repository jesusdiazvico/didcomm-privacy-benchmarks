set terminal png size 800,800
set output 'results-size.png'
set xlabel "Number of recipients" font ",16"
set ylabel "DIDComm msg size (bytes)" font ",16"
set key right bottom
set key spacing 1.5
set xtics 1 font ",14"
set ytics font ",14"
plot \
"results.anon" u 1:6:7 with errorlines lw 2 pt 9 ps 2 linecolor rgb "red" title "anon", \
"results.auth" u 1:6:7 with errorlines lw 2 pt 2 ps 2 linecolor rgb "blue" title "auth", \
"results.naiveaa" u 1:6:7 with errorlines lw 2 pt 65 ps 2 linecolor rgb "green" title "naive-a-auth", \
"results.mergeaa" u 1:6:7 with errorlines lw 2 pt 4 ps 2 linecolor rgb "orange" title "merge-a-auth", \
"results.raa" u 1:6:7 with errorlines lw 2 pt 5 ps 2 linecolor rgb "black" title "r-anon", \
"results.raauth" u 1:6:7 with errorlines lw 2 pt 6 ps 2 linecolor rgb "purple" title "ra-a-auth"


#!/bin/bash
if [ "$#" -ne 3 ]; then
	echo "Usage: $0 <mode=[anon|auth|naive-a-auth|merge-a-auth|ra-anon|ra-a-auth]> <niters> <output_file>"
	exit 0
fi

echo "# Results for $1 mode" > $3
echo "# Results averaged over $2 iterations" >> $3
echo -e "# nRecipients\tMax_mem_avg\tMax_mem_std" >> $3

if [ "$1" = "anon" ]; then
	for i in {1..6}; do
		for j in $(seq 1 $2); do
			`python anon-mem.py "Hello" $i >> $3.$2.$i`
		done
		awk -v nrecs=$i 'BEGIN {sum=0; i=0} { rows[i]=$1; sum+=$1; i++ } END { avg=sum/NR; std=0; for(j=0;j<NR;j++) {std += (rows[j]-avg)^2} std=sqrt(std/NR); print nrecs"\t"avg"\t"std }' $3.$2.$i >> $3
		rm $3.$2.$i	
	done
elif [ "$1" = "auth" ]; then
	for i in {1..6}; do
		for j in $(seq 1 $2); do
			`python auth-mem.py "Hello" $i >> $3.$2.$i`
		done
		awk -v nrecs=$i 'BEGIN {sum=0; i=0} { rows[i]=$1; sum+=$1; i++ } END { avg=sum/NR; std=0; for(j=0;j<NR;j++) {std += (rows[j]-avg)^2} std=sqrt(std/NR); print nrecs"\t"avg"\t"std }' $3.$2.$i >> $3
		rm $3.$2.$i
	done
elif [ "$1" = "naive-a-auth" ]; then
	for i in {1..6}; do
		for j in $(seq 1 $2); do
			`python naive-a-auth-mem.py "Hello" $i >> $3.$2.$i`
		done
		awk -v nrecs=$i 'BEGIN {sum=0; i=0} { rows[i]=$1; sum+=$1; i++ } END { avg=sum/NR; std=0; for(j=0;j<NR;j++) {std += (rows[j]-avg)^2} std=sqrt(std/NR); print nrecs"\t"avg"\t"std }' $3.$2.$i >> $3
		rm $3.$2.$i	
	done
elif [ "$1" = "merge-a-auth" ]; then
	for i in {1..6}; do
		for j in $(seq 1 $2); do
			`python merge-a-auth-mem.py "Hello" $i >> $3.$2.$i`
		done
		awk -v nrecs=$i 'BEGIN {sum=0; i=0} { rows[i]=$1; sum+=$1; i++ } END { avg=sum/NR; std=0; for(j=0;j<NR;j++) {std += (rows[j]-avg)^2} std=sqrt(std/NR); print nrecs"\t"avg"\t"std }' $3.$2.$i >> $3
		rm $3.$2.$i	
	done
elif [ "$1" = "ra-anon" ]; then
	for i in {1..6}; do
		for j in $(seq 1 $2); do
			`python ra-anon-mem.py "Hello" $i >> $3.$2.$i`
		done
		awk -v nrecs=$i 'BEGIN {sum=0; i=0} { rows[i]=$1; sum+=$1; i++ } END { avg=sum/NR; std=0; for(j=0;j<NR;j++) {std += (rows[j]-avg)^2} std=sqrt(std/NR); print nrecs"\t"avg"\t"std }' $3.$2.$i >> $3
		rm $3.$2.$i	
	done
elif [ "$1" = "ra-a-auth" ]; then
	for i in {1..6}; do
		for j in $(seq 1 $2); do
			`python ra-a-auth-mem.py "Hello" $i >> $3.$2.$i`
		done
		awk -v nrecs=$i 'BEGIN {sum=0; i=0} { rows[i]=$1; sum+=$1; i++ } END { avg=sum/NR; std=0; for(j=0;j<NR;j++) {std += (rows[j]-avg)^2} std=sqrt(std/NR); print nrecs"\t"avg"\t"std }' $3.$2.$i >> $3
	done

else
	echo "Unknown mode."
fi



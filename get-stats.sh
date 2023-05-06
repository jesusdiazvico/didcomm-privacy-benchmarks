
#!/bin/bash
if [ "$#" -ne 2 ]; then
	echo "Usage: $0 <niters> <output_file>"
	exit 0
fi

echo "# Results for naive anoncrypt(authcrypt(m)) mode" > $2 # results.naiveaa
echo "# Results averaged over $1 iterations" >> $2 # results.naiveaa
echo -e "# nRecipients\tPack_avg\tPack_std\tUnpack_avg\tUnpack_std\tSize_avg\tSize_std" >> $2 #results.naiveaa
for i in {1..4}; do 
	`python benchmarks.py $i $1 >> $2` #results.naiveaa`
done

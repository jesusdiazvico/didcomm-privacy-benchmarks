
#!/bin/bash
if [ "$#" -ne 3 ]; then
	echo "Usage: $0 <mode=[anon|auth|naive-a-auth|merge-a-auth|ra-anon|ra-a-auth]> <niters> <output_file>"
	exit 0
fi

echo "# Results for $1 mode" > $3
echo "# Results averaged over $2 iterations" >> $3
echo -e "# nRecipients\tPack_avg\tPack_std\tUnpack_avg\tUnpack_std\tSize_avg\tSize_std" >> $3

if [ "$1" = "anon" ]; then
	for i in {1..6}; do
		`python anon.py "Hello" $i $2 >> $3`
	done
elif [ "$1" = "auth" ]; then
	for i in {1..6}; do
		`python auth.py "Hello" $i $2 >> $3`
	done
elif [ "$1" = "naive-a-auth" ]; then
	for i in {1..6}; do
		`python naive-a-auth.py "Hello" $i $2 >> $3`
	done
elif [ "$1" = "merge-a-auth" ]; then
	for i in {1..6}; do
		`python merge-a-auth.py "Hello" $i $2 >> $3`
	done
elif [ "$1" = "ra-anon" ]; then
	for i in {1..6}; do
		`python ra-anon.py "Hello" $i $2 >> $3`
	done
elif [ "$1" = "ra-a-auth" ]; then
	for i in {1..6}; do
		`python ra-a-auth.py "Hello" $i $2 >> $3`
	done

else
	echo "Unknown mode."
fi

join:
	cat pieces/x* > alpine.qcow2.gz

split:
	rm -rf pieces
	mkdir -p pieces
	( cd pieces; split -b1m ../alpine.qcow2.gz )

clean:
	alpine.qcow2.gz

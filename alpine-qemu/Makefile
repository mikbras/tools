
all:

split:
	rm -rf pieces
	mkdir -p pieces
	( cd pieces; split -b1m ../alpine.qcow2.gz )

join:
	cat pieces/x* > alpine.gcow2.gz

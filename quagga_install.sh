kill $(ps aux | grep bgpd |  head -2 | awk '{print $2}')
kill $(ps aux | grep zebra -d |  head -2 | awk '{print $2}')
make clean
./configure --enable-user=root --enable-group=root
make 
make install
zebra -d
bgpd


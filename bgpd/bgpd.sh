kill $(ps aux | grep bgpd |  head -2 | awk '{print $2}')
make 
make install
bgpd


sudo apt update
sudo apt install build-essential dkms linux-headers-$(uname -r) automake autoconf libtool
sudo apt install zlib1g-dev libbz2-dev libncurses5-dev libncursesw5-dev libssl-dev
sudo apt install build-essential autoconf automake libtool libcurl4-openssl-dev libjansson-dev libssl-dev libgmp-dev
git clone https://github.com/tpruvot/cpuminer-multi.git
cd cpuminer-multi
cp /home/mint/cpu/sha2_26.c /home/mint/cpuminer-multi/algo/sha2.c
cp /home/mint/cpu/pp-btc-watchdog.sh /home/mint/cpuminer-multi/pp-btc-watchdog.sh
chmod 755 pp-btc-watchdog.sh
export CPPFLAGS="-I/usr/include/openssl"
export LDFLAGS="-L/usr/lib/x86_64-linux-gnu"
export OPENSSL_LIBS="-lssl -lcrypto"
./build.sh

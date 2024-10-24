# Build 
mkdir -p build; cd build
cmake -DPICOQUIC_FETCH_PTLS=Y .
make

# Run sample transactions

cd ./build
make; python3 ../sample/send_transaction.py | ./picoquic_sample client

# Run real transactions

cd ../sig
zig build run --  test-transaction-sender -n testnet 2>&1 | tee test/out.log | grep ^cin: | ../picoquic/build/picoquic_sample client 
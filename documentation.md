# Container / VM setup
## For containers:
```
$ cd network_test
$ ./setup_network_docker.sh
```
## For VMs:
Before running the setup script, ensure that the VMs are up and running, otherwise the script will fail when trying to configure the network interfaces in the VMs. Then run:
```
$ cd network_test
$ ./setup_network_vm.sh
```
Then enable the second NIC in the VMs to allow them to communicate through the KMS and SDN controller.
For the server/receiver VM, run:
```
$ sudo ip addr add 172.30.0.20/24 dev enp8s0 
$ sudo ip link set enp8s0 up
$ sudo ip route add 172.20.0.0/24 via 172.30.0.100 dev enp8s0
```
For the client/sender VM, run:
```
$ sudo ip addr add 172.20.0.10/24 dev enp8s0
$ sudo ip link set enp8s0 up
$ sudo ip route add 172.30.0.0/24 via 172.20.0.100 dev enp8s0
```

# Implemented network topologies in QKDNetSim
## Distributed KMS with only P2P links between QKD modules and local KMS, with central SDN controller
```
 Network topology (2-KMS / Point-to-Point / 7 Nodes)

                 [Global QKDN Controller]
                        (Node n6)
          (Logical Control Plane - Out of Band)

    docker(Master)                              docker(Slave)
     (tap0)                                         (tap1)
      |                                               |
     n4                                              n5
 (sdnAgent)                                      (sdnAgent)
      :                                               :
  n2 ----------------------------------------------- n3 
 (Master KMS)                                  (Slave KMS)
   |                                                  |
  n0---------------------qkd-------------------------n1 
 (QKD Master)                                  (QKD Slave)
```

## Centralised KMS with only P2P links between QKD modules and central KMS, with central SDN controller
 Network topology (2-KMS / Point-to-Point / 8 Nodes)

                 [Global QKDN Controller]
                        (Node n6)
          (Logical Control Plane - Out of Band)

                 [Global KMS Controller]
                        (Node n7)
          (XOR logic for key aggregation - Out of Band)

    docker(Master)                              docker(Slave)
     (tap0)                                         (tap1)
      |                                               |
     n4                                              n5
 (sdnAgent)                                      (sdnAgent)
      :                                               :
  n2 ----------------------------------------------- n3 
 (Master KMS)                                  (Slave KMS)
   |                                                  |
  n0---------------------qkd-------------------------n1 
 (QKD Master)                                  (QKD Slave)


## Distributed KMS with n trusted relays between QKD modules and local KMS, with central SDN controller
```
 Network topology (6-KMS / 4-Trusted Relays)

                            [Global QKDN Controller (QCenController)]
                            (Logical Control Plane - Out of Band)

    docker(Master)                                                      docker(Slave)
     (tap0)                                                                 (tap1)
      |                                                                       |
     n12         n13         n14         n15         n16         n17          |
 (sdnAgent)  (sdnAgent)  (sdnAgent)  (sdnAgent)  (sdnAgent)  (sdnAgent)       |
      :           :           :           :           :           :           |
  n6 ----------- n7 -------- n8 -------- n9 -------- n10 -------- n11         |
 (Master       (Trusted    (Trusted    (Trusted    (Trusted      (Slave       |
  KMS)          1 KMS)      2 KMS)      3 KMS)      4 KMS)        KMS)        |
   |              |           |           |           |           |           |
  n0----qkd------n1---qkd----n2---qkd----n3---qkd----n4---qkd----n5           |
 (QKD            (QKD        (QKD        (QKD        (QKD        (QKD         |
 Master)          T1)         T2)         T3)         T4)        Slave)       |
```

## Centralised KMS with n trusted relays between QKD modules and central KMS, with central SDN controller
```
 Network topology (6-KMS / 4-Trusted Relays / 1 Central KMA)
 [Global QKDN Controller (QCenController)]
                            (Logical Control Plane - Out of Band)

    docker(Master)                                                      docker(Slave)
     (tap0)                                                                 (tap1)
      |                                                                       |
      |                                                                       |
      +-----------+-----------+-----------+---+-------+-----------+-----------+
      |           |           |           |           |           |           |
     n12         n13         n14         n15         n16         n17         n19
 (sdnAgent)  (sdnAgent)  (sdnAgent)  (sdnAgent)  (sdnAgent)  (sdnAgent)  (sdnAgent)
      :           :           :           :           :           :           :
      :           :           :           :           :     
         :           :           :           :           :        | 
   |              :           :           :           :           :        |
  n6 ----------- n7 -------- n8 -------- n9 -------- n10 -------- n11      :
 (Master       (Trusted    (Trusted    (Trusted    (Trusted      (Slave    :
  KMS)          1 KMS)      2 KMS)      3 KMS)      4 KMS)        KMS)     :
   | \            | \         | \         | /         | /         | /      :
   |  \___________|__\________|__\_______/__|________/__|________/  /      :
   |              |           |        n18          |           |          :
   |              |     (Central KMA / XOR Aggregator)          |          :
   |              |                       |           |           |        :
  n0----qkd------n1---qkd----n2---qkd----n3---qkd----n4---qkd----n5        :
 (QKD            (QKD        (QKD        (QKD        (QKD        (QKD      :
 Master)          T1)         T2)         T3)         T4)        Slave)    :
```

# List of commands to install wolfssl 5.8.4 stable

## Install wolfssl 5.8.4 stable

### Clone repo

```
$ git clone https://github.com/graziadonghia/wolfssl.git

$ cd wolfssl

$ git checkout tags/v5.8.4-stable

$ git checkout -b pqc_qkd
```

### Install dependencies, configure and build

```
$ apt install libtool automake autoconf cmake
$ ./autogen.sh
$ ./configure \
--enable-dtls \
--enable-aesgcm \
--enable-certgen \
--enable-certext \
--enable-certreq \
--enable-psk \
--enable-pkcs11 \
--enable-pkcs7 \
--enable-testcert \
--disable-tlsv12 \
--disable-oldtls \
--enable-tls13 \
--enable-sp-math \
--enable-kyber \
--enable-session-ticket \
--enable-dilithium
$ make all
```
## Test PQ TLS using wolfssl

### Generate PQ certificate using OQS container
```
$ docker run -it --rm -v $(pwd):/shared openquantumsafe/oqs-ossl3 sh

/# openssl req -x509 -new -newkey mldsa87 -keyout /shared/mldsa87_ca.key -out /shared/mldsa87_ca.crt -nodes -subj "/CN=PQ Root CA" -days 365 

/# openssl req -new -newkey mldsa65 -keyout /shared/mldsa65_server.key -out /shared/mldsa65_server.csr -nodes -subj "/CN=localhost" 

/# openssl x509 -req -in /shared/mldsa65_server.csr -out /shared/mldsa65_server.crt -CA /shared/mldsa87_ca.crt -CAkey /shared/mldsa87_ca.key -CAcreateserial -days 365

```
### Run wolfssl server and client examples with the generated PQ certs

The flag `-b` binds with any interface. Run this on the server side:
```
$ ./examples/server/server -v 4 -b -c certs/pq_certs/mldsa65_server.crt -k certs/pq_certs/mldsa65_server.key --pqc ML_KEM_1024 -s -j -l TLS13-AES256-GCM-SHA384
```
And run this on the client side:
```
$ ./examples/client/client -v 4 -h 172.20.0.10 -A certs/pq_certs/mldsa87_ca.crt --pqc ML_KEM_1024 -s -l TLS13-AES256-GCM-SHA384
```
For mutual authentication:
```
$ ./examples/client/client -v 4 -h 172.30.0.20 -c certs/pq_certs/mldsa65_client.crt -k certs/pq_certs/mldsa65_client.key -A certs/pq_certs/mldsa87_client_ca.crt --pqc ML_KEM_1024 -s -l TLS13-AES256-GCM-SHA384
```

For session resumption:
```
$ ./examples/server/server -v 4 -b -c certs/pq_certs/mldsa65_server.crt -k certs/pq_certs/mldsa65_server.key --pqc ML_KEM_1024 -s -j -l TLS13-AES256-GCM-SHA384 -i --send-ticket

$ ./examples/client/client -v 4 -h 172.30.0.20 -c certs/pq_certs/mldsa65_client.crt -k certs/pq_certs/mldsa65_client.key -A certs/pq_certs/mldsa87_client_ca.crt --pqc ML_KEM_1024 -s -l TLS13-AES256-GCM-SHA384 --wait-Ticket
``` 
Then, once the client receives the session ticket, run the client command again with the `-r` flag to test session resumption:
```
$ ./examples/client/client -v 4 -h 172.30.0.20 -c certs/pq_certs/mldsa65_client.crt -k certs/pq_certs/mldsa65_client.key -A certs/pq_certs/mldsa87_client_ca.crt --pqc ML_KEM_1024 -s -l TLS13-AES256-GCM-SHA384 -r
```

## Compile wolfssl for IoT testbed
### For ARM-A8 architecture
#### Generate Binary file
```
$ make clean
$ ./configure \
            --build=x86_64-pc-linux-gnu \
            --host=arm-linux-gnueabihf \
            CC=arm-linux-gnueabihf-gcc \
            AR=arm-linux-gnueabihf-ar \
            STRIP=arm-linux-gnueabihf-strip \
            RANLIB=arm-linux-gnueabihf-ranlib \
            --enable-dtls \
            --enable-aesgcm \
            --enable-certgen \
            --enable-certext \
            --enable-certreq \
            --enable-psk \
            --enable-pkcs11 \
            --enable-pkcs7 \
            --enable-testcert \
            --disable-tlsv12 \
            --disable-oldtls \
            --enable-tls13 \
            --enable-sp-math \
            --enable-sp \
            --enable-kyber \
            --enable-session-ticket \
            --enable-dilithium \
            --disable-shared \
            --enable-static
$ make -j$(nproc) CFLAGS="-fno-pie" LDFLAGS="-all-static -no-pie"
```
To check that the compilation successfully generated the binary file, you should see this exact output:
```
$ file ./examples/client/client
./examples/client/client: ELF 32-bit LSB executable, ARM, EABI5 version 1 (GNU/Linux), statically linked, BuildID[sha1]=d953f20ba031d973ba06f6b3fe203d69626ed937, for GNU/Linux 3.2.0, not stripped
$ file ./examples/server/server
./examples/server/server: ELF 32-bit LSB executable, ARM, EABI5 version 1 (GNU/Linux), statically linked, BuildID[sha1]=9b76978f5c009cc42f11f21e3fcb3df139ca28de, for GNU/Linux 3.2.0, not stripped
```
#### Copy the binary to the IoT testbed
Assuming that you already created an account on FIT IoT-LAB, create a new experiment with the a8 architecture with 2 nodes (one for the client, one for the server).
Move the previously generated binaries to the Testbed frontend:
``` 
$ scp ./examples/client/client <your_username>@saclay.iot-lab.info:~/
$ scp ./examples/server/server <your_username>@saclay.iot-lab.info:~/
```
SSH into the frontend server
```
$ ssh <your_username>@saclay.iot-lab.info
```
Move the binaries to the physical A8 nodes: let's assume that your nodes are node-a8-100 (server) and node-a8-101 (client)
```
scp ~/server root@node-a8-100:~/
scp ~/client root@node-a8-101:~/
```

Now open two terminals, run the programs and save the experimental data to a csv file
```
$ ssh root@node-a8-100 "./server" > server_metrics.csv
$ ssh root@node-a8-101 "./client" > client_metrics.csv
```
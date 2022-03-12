# HomPSI

HomPSI is a Homomorphic Public Set Intersection utility written in C++. It is based on the Microsoft SEAL library.
- [Requirements](#requirements)
- [Build](#build)
- [Documentation](#documentation)

## Requirements
The HomPSI utility requires to be compiled in a system with Microsoft SEAL and protobuf installed.

## Build
Before building the executable run make in order to compile the protocol buffer.

## Documentation

### Setup
The setup command is used to setup encryption parameters and keys. 

Flags:
- -k: public key output file (default: pub.key)
- -s: secret key output file (default: sec.key)
- -p: parameters output file (default: params.par)
- -r: relinearization output file (default: relin.key)
- -y: poly modulus degree (default: 8192, possible values {4096, 8192, 16384, 32768})
- -l: plai modulus degree (default: 1024, should be as small as possible do decreese noise consumption)
```console
$ HomPSI setup -k pub.key -s sec.key -p params.par -r relin.key
$ HomPSI setup
```

###Encrypt
This command is used by the sender to encrypt a file. The encryption is done for every row of the file.

Flags: 
- -k: public key file (default: pub.key)
- -i: input file (default: receiver.csv)
- -p: parameters file (default: params.par)
- -o: output file (default: receiver.pb)

```console
$ HomPSI encrypt -k pub.key -i input.csv -p params.par -o rec.pb
$ HomPSI encrypt
```

###Inter
This command is used bu the sender to do the intersection between the encrypted dataset and the sender dataset.

Flags:
- -k: public key file (default: pub.key)
- -i: input file (default: sender.csv)
- -p: parameters file (default: params.par)
- -o: output file (default: sender.pb)
- -r: relinearization key file (default: relin.key)
- -b: input ciphers file (default: receiver.pb)
```console
$ HomPSI inter -k pub.key -i input.csv -p params.par -o sender.pb
$ HomPSI inter
```

###Receive
This command is used by the receiver to check the intersection.

Flags:
- -k: secret key file (default: sec.key)
- -i: receiver plaintext file (default: receiver.csv)
- -p: parameters file (default: params.par)
- -o: output file (default: intersection.csv)
- -b: input sender ciphers file (default: sender.pb)
```console
$ HomPSI receive -k sec.key -i input.csv -p params.par -o sender.pb
$ HomPSI receive
```
# Modbus Security CLI

## Building the Docker Image

To build the Docker image, use the following command:

```sh
docker build -t modbus-security-cli .
```

## Using the PKI Directory

The PKI directory is located at `/app/pki` in the container and is automatically populated with the necessary certificates and keys when the container is run:
- `ca.pfx`: the KeyStore containing the CA certificate and private key.
- `server.pfx`: the KeyStore containing the server certificate and private key.
- `client1.pfx`: the KeyStore containing the "ReadOnly" client certificate and private key.
- `client2.pfx`: the KeyStore containing the "ReadWrite" client certificate and private key.

These are additionally available in OpenSSL friendly PEM formats:
- `ca.crt`: the CA certificate in PEM format.
- `ca.key`: the CA private key in PKCS#8 (PEM) format.
- `server.crt`: the server certificate in PEM format.
- `server.key`: the server private key in PKCS#8 (PEM) format.
- `client1.crt`: the "ReadOnly" client certificate in PEM format.
- `client1.key`: the "ReadOnly" client private key in PKCS#8 (PEM) format.
- `client1.crt`: the "ReadWrite" client certificate in PEM format.
- `client1.key`: the "ReadWrite" client private key in PKCS#8 (PEM) format.

You can mount this directory to a host volume at `/tmp/pki` to persist the certificates and keys.

## Running a Container for the Server Command

To run a container for the server command, use the following command:

```sh
docker run --rm -it -v /tmp/pki:/app/pki modbus-security-cli:latest server
```

This command mounts the host directory `/tmp/pki` to the container's `/app/pki` directory.

## Running a Container for the Client Command

To run a container for the client command, use the following command:

```sh
docker run --rm -it -v /tmp/pki:/app/pki modbus-security-cli:latest client <host> <command>
```

Replace `<host>` with the actual hostname or IP address of the server you want to connect to. This command also mounts the host directory `/tmp/pki` to the container's `/app/pki` directory.

`<command>` can be one of the following:
- `rhr <address> <quantity>`: read holding registers
- `wsr <address> <value>`: write single register

## Example Session
Start a server:
```
> docker run --rm -it -p 802:802 --name modbus-server -v /tmp/pki:/app/pki modbus-security-cli:latest server
[main] INFO ModbusSecurityServer - Modbus Security server listening on port 802
```

In another terminal, connect to the server and read holding registers:
```
> docker run --rm -it -v /tmp/pki:/app/pki modbus-security-cli:latest client host.docker.internal rhr 1 10
Connected to host.docker.internal:802
-> ReadHoldingRegistersRequest[address=1, quantity=10]
<- ReadHoldingRegistersResponse[registers=0000000000000000000000000000000000000000]
Disconnected
```

Try to write a single register with the "ReadOnly" certificate:
```
> docker run --rm -it -v /tmp/pki:/app/pki modbus-security-cli:latest client host.docker.internal wsr 1 42
Connected to host.docker.internal:802
-> WriteSingleRegisterRequest[address=1, value=42]
0x06 [WRITE_SINGLE_REGISTER] generated exception response 0x01 [ILLEGAL_FUNCTION]
Disconnected
```

Write a single register with the "ReadWrite" certificate:
```
> docker run --rm -it -v /tmp/pki:/app/pki modbus-security-cli:latest client --client-key-store=./pki/client2.pfx host.docker.internal wsr 1 42
Connected to host.docker.internal:802
-> WriteSingleRegisterRequest[address=1, value=42]
<- WriteSingleRegisterResponse[address=1, value=42]
Disconnected
```

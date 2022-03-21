# Hybrid KEMTLS tests

## Introduction

This repository aims to experiment, measure and compare the experimental Hybrid KEMTLS implementation, made in the Go standard library.

Before running the experiments, it is required that you have this Hybrid KEMTLS Go Standard Library available in your system. To do so, perform the following steps:

1. Install dependencies:
```
sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml pkg-config git
```

2. Install the Go language
> [https://go.dev/doc/install](https://go.dev/doc/install)
>
> The Go binary will be added temporarily to your PATH, to make it permanent append it to your `~/.profile `

3. Clone the Hybrid KEMTLS Go Standard Library repository;

4. Checkout to the `hybrid_kemtls_bindings` branch: `$ git checkout hybrid_kemtls_bindings`

5. Run the installation script: `. install.sh`
> You must precisely follow this syntax, in order to execute the script under the current shell
>
> It will clone and compile Liboqs and Liboqs-Go, and compile Hybrid KEMTLS Go
>
> The Go compilation will result in a Go binary which will be added to your PATH

The resultant Go binary will be used to compile and run the code from this repository

## Test Environment

The following algorihtms are available for the server and the client:

**Key Exchange algorithms:**

```
Kyber512, P256_Kyber512, Kyber768, P384_Kyber768,
Kyber1024, P521_Kyber1024, LightSaber_KEM, P256_LightSaber_KEM,
Saber_KEM, P384_Saber_KEM, FireSaber_KEM, P521_FireSaber_KEM,
NTRU_HPS_2048_509, P256_NTRU_HPS_2048_509,
NTRU_HPS_2048_677, P384_NTRU_HPS_2048_677,
NTRU_HPS_4096_821, P521_NTRU_HPS_4096_821,
NTRU_HPS_4096_1229, P521_NTRU_HPS_4096_1229,
NTRU_HRSS_701, P384_NTRU_HRSS_701, NTRU_HRSS_1373, P521_NTRU_HRSS_1373,
```

**Authentication algorithms:**
```
P256_Dilithium2, P384_Dilithium3, P521_Dilithium5
P256_Falcon512, P521_Falcon1024
```

There are three programs: `launch_server`, `launch_client`, `gobench`, `generate_root`

The first step is to create a Root CA to be used by the server and the client. For that, the `generate_cert.go` will be used.

<br/>

## `generate_root.go`:

Generates a Root CA to be used in the tests. If the Root CA uses classic algorithms, it will be generated PEM encoded files for the certificate and the private key. If the Root CA uses hybrid algorithms, it will be generated a text file with the Root CA data, so the server and the client script can reconstruct the CA in runtime. This is a workaround to avoid modification in the certificate encoding package of the Go Standard Library.

The Root CA files are written to the `root_ca/` directory.

### Required flags:

`-rootalgo`:

<br/>

## `launch_server.go`:

Launches various TLS servers for each combination of the Key Exchange and Authentication algorithms that are in the same security level (when performing KEMTLS, the same algorithm is used for the key exchange and authentication).

The TLS servers will perform Hybrid KEMTLS or Hybrid PQTLS, depending on the flags that it receives.


### Required flags

`-ipserver`: IP address of the server

If the Root CA is Hybrid Root CA, the following flag must be set to the hybrid algorithm

`-hybridroot`: Hybrid Root CA algorithm family name
> Possible values:
>
> dilithium, falcon

If the Root CA uses classical algorithms, the following flags must be set:

`-rootcert`: Path to the root CA certificate PEM file

`-rootkey`: Path to the root CA private key PEM file

If the `-http` flag is true, it must be supplied the Key Exchange and the Authentication algorithms, with the following flags:

`-kex`: Key Exchange algorithm

`-authserver`: Authentication algorithm

### Optional flags

`-http`: Instantiate an HTTP server that serves the page `static/index.html` at `:4433`

`-pqtls`: Instantiate a PQTLS server. 
> If not present, then a KEMTLS server is instantiated by default

`-clientauth`: Server will require mutual authentication

`-handshakes`: Number of handshakes that the server will measure the timings and save it in a csv.

`-cachedcert`: Server will perform KEMTLS-PDK

<br/>



## `launch_client.go`:

It will instantiate a TLS client (for non-HTTP server) that will perform a number of handshakes, specified by `-handshakes`, with the TLS server specified by `-ipclient` for each combination of the Key Exchange and Authentication algorithms that are in the same security level (when performing KEMTLS, the same algorithm is used for the key exchange and authentication): 

### Required flags

`-ipserver:` IP address of the server

If the Root CA is Hybrid Root CA, the following flag must be set to the hybrid algorithm

`-hybridroot`: Hybrid Root CA algorithm family name

If the Root CA uses classical algorithms, the following flags must be set:

`-rootcert`: Path to the root CA certificate PEM file

`-rootkey`: Path to the root CA private key PEM file

### Optional flags

`-pqtls`: Instantiate a PQTLS client. 
> If not present, then a KEMTLS client is instantiated by default

`-clientauth`: Client will perform mutual authentication

`-ipclient`: IP address of the client to be used in the client certificate

`-handshakes`: Number of handshakes that the client will perform 

`-cachedcert`: Client will perform KEMTLS-PDK


<br/>



## `gobench.go`

Perform HTTP Load Tests. It is based on the already existing gobench tool, available at [https://github.com/cmpxchg16/gobench](https://github.com/cmpxchg16/gobench), with some minor modifications to integrate it in our tests.

### Required flags

`-benchkex`: Key Exchange algorithm

`-benchauth`: Authentication algorithm

`-u`: URL of the server

`-t`: Period of time (in seconds) of the test

If the Root CA is Hybrid Root CA, the following flag must be set to the hybrid algorithm

`-hybridroot`: Hybrid Root CA algorithm family name

If the Root CA uses classical algorithms, the following flags must be set:

`-rootcert`: Path to the root CA certificate PEM file

`-rootkey`: Path to the root CA private key PEM file


### Optional flags

`-pqtls`: Instantiate a PQTLS client. If not present, then a KEMTLS client is instantiated

`-clientauth`: Client will perform mutual authentication

`-cachedcert`: Load test with KEMTLS-PDK

`-k`: Do HTTP keep-alive

`-c`: Number of concurrent clients

> **Note:** the following arguments were not used in our measurements.

`-r`: Number of requests per client

`-f`: URL's file path (line seperated)

`-d`: HTTP POST data file path

`-tw`: Write timeout (in milliseconds)

`-tr`: Read timeout (in milliseconds)

`-auth`: Authorization header


## Examples

The following examples assume you have the Hybrid KEMTLS Go binary in your PATH. If you don't have it, instead of simply calling `go` you must pass the path to the Hybrid KEMTLS Go binary.

Execute them in the `src/` directory.

### Generating Root CA

The Root CAs can be generated with the `gen_all_root.sh` script. Run it from the `scripts/` dir:
```
./gen_all_roots.sh
```


### Hybrid KEMTLS

**Server:**
```
go run launch_servers.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-ipserver 127.0.0.1 \
-handshakes 10 \
-hybridroot dilithium
```

**Client:**
```
go run launch_client.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-ipclient 127.0.0.1 \
-ipserver 127.0.0.1 \
-handshakes 10 \
-hybridroot dilithium
```

### Hybrid PQTLS

**Server:**
```
go run launch_servers.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-ipserver 127.0.0.1 \
-handshakes 10 \
-hybridroot dilithium \
-pqtls
```

**Client:**
```
go run launch_client.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-ipclient 127.0.0.1 \
-ipserver 127.0.0.1 \
-handshakes 10 \
-hybridroot dilithium \
-pqtls
```

### HTTP Load Test

**(Hybrid KEMTLS) Server:**
```
go run launch_servers.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-ipserver 127.0.0.1 \
-kex P256_Kyber512 \
-hybridroot dilithium \
-http
```

**(Hybrid KEMTLS) Gobench:**
```
go run gobench.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-benchkex P256_Kyber512 \
-benchauth P256_Kyber512 \
-hybridroot dilithium \
-k=true \
-u https://127.0.0.1:4433 \
-c 10 \
-t 5 
```

Alternatively, it can be used the scripts in the `scripts/` directory:

`config.sh` defines the `COMMON_FLAGS` variable, which holds the common flags for the server, client and gobench
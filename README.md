# Hybrid KEMTLS tests

## Introduction

This repository aims to experiment, measure and compare the experimental Hybrid KEMTLS implementation, made in the Go standard library.

Before running the experiments, it is required that you have this experimental Go Standard Library available in your system. To do so, perform the following steps:

1. Install the Go language
> [https://go.dev/doc/install](https://go.dev/doc/install)
2. Clone the Experimental Go Standard Library repository;
3. Go to the `src/` directory, from the root of the repository;
4. Run the compilation script: `$ ./make.bash`
> (The `$` indicates that it is a command to be executed in a terminal)\
> The compilation will result in the following binary: `bin/go` (path relative to the root of the repository)

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

### Required flags:

`-rootalgo`:

### Optional flags:

`-hybrid`: Generates a Hybrid Root


<br/>

## `launch_server.go`:

Launches various TLS servers for each combination of the Key Exchange and Authentication algorithms that are in the same security level (when performing KEMTLS, the same algorithm is used for the key exchange and authentication).

The TLS servers will perform Hybrid KEMTLS or Hybrid PQTLS, depending on the flags that it receives.


### Required flags

`-ipserver`: IP address of the server

If the Root CA is Hybrid Root CA, the following flag must be set to the hybrid algorithm

`-hybridroot`: Hybrid Root CA algorithm

If the Root CA uses classical algorithms, the following flags must be set:

`-rootcert`: Path to the root CA certificate PEM file

`-rootkey`: Path to the root CA private key PEM file

If the `-http` flag is true, it must be supplied the Key Exchange and the Authentication algorithms, with the following flags:

`-kex`: 
`-auth`:

### Optional flags

`-http`: Instantiate an HTTP server that serves the page `static/index.html` at `:4433`

`-pqtls`: Instantiate a PQTLS server. 
> If not present, then a KEMTLS server is instantiated by default

`-clientauth`: Server will require mutual authentication

`-handshakes`: Number of handshakes that the server will measure the timings and save it in a csv.

<br/>



## `launch_client.go`:

It will instantiate a TLS client (for non-HTTP server) that will perform a number of handshakes, specified by `-handshakes`, with the TLS server specified by `-ipclient` for each combination of the Key Exchange and Authentication algorithms that are in the same security level (when performing KEMTLS, the same algorithm is used for the key exchange and authentication): 

### Required flags

`-ipserver:` IP address of the client

If the Root CA is Hybrid Root CA, the following flag must be set to the hybrid algorithm

`-hybridroot`: Hybrid Root CA algorithm

If the Root CA uses classical algorithms, the following flags must be set:

`-rootcert`: Path to the root CA certificate PEM file

`-rootkey`: Path to the root CA private key PEM file

### Optional flags

`-pqtls`: Instantiate a PQTLS client. 
> If not present, then a KEMTLS client is instantiated by default

`-clientauth`: Client will perform mutual authentication

`-ipclient`: IP address of the client to be used in the client certificate

`-handshakes`: Number of handshakes that the client will perform 



<br/>



## `gobench.go`

Perform HTTP Load Tests. It is based on the already existing gobench tool, available at [https://github.com/cmpxchg16/gobench](https://github.com/cmpxchg16/gobench), with some minor modifications to integrate it in our tests.

### Required flags

`-benchkex`: KEX algorithm

`-benchauth`: Authentication algorithm

`-u`: URL of the server

`-t`: Period of time (in seconds) of the test

If the Root CA is Hybrid Root CA, the following flag must be set to the hybrid algorithm

`-hybridroot`: Hybrid Root CA algorithm

If the Root CA uses classical algorithms, the following flags must be set:

`-rootcert`: Path to the root CA certificate PEM file

`-rootkey`: Path to the root CA private key PEM file


### Optional flags

`-pqtls`: Instantiate a PQTLS client. If not present, then a KEMTLS client is instantiated

`-clientauth`: Client will perform mutual authentication

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

### Hybrid KEMTLS

**Server:**
```
go run launch_servers.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-ipserver 127.0.0.1 \
-handshakes 10 \
-hybridroot P256_Dilithium2
```

**Client:**
```
go run launch_client.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-ipclient 127.0.0.1 \
-ipserver 127.0.0.1 \
-handshakes 10 \
-hybridroot P256_Dilithium2
```

### Hybrid PQTLS

**Server:**
```
go run launch_servers.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-ipserver 127.0.0.1 \
-handshakes 10 \
-hybridroot P256_Dilithium2
-pqtls
```

**Client:**
```
go run launch_client.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-ipclient 127.0.0.1 \
-ipserver 127.0.0.1 \
-handshakes 10 \
-hybridroot P256_Dilithium2
-pqtls
```

### HTTP Load Test

**(Hybrid KEMTLS) Server:**
```
go run launch_servers.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go \
-ipserver 127.0.0.1 \
-serverkex P256_Kyber512
-hybridroot P256_Dilithium2
-http
```

**(Hybrid KEMTLS) Gobench:**
```
go run gobench.go hybrid_server_kemtls.go parse_hybrid_root.go stats_pqtls.go stats_kemtls.go plot_functions.go 
-kex P256_Kyber512 \
-authalgo P256_Kyber512 \
-hybridroot P256_Dilithium2 \
-k=true \
-u https://127.0.0.1:4433 \
-c 10 \
-t 5 

```

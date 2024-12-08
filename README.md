# Hybrid KEMTLS tests

## Installation

This repository aims to experiment, measure and compare the experimental Hybrid KEMTLS implementation, made in the Go standard library.

Before running the experiments, it is required that you have this Hybrid KEMTLS Go Standard Library available in your system. To do so, perform the following steps (assuming Bash Shell):

1. Install dependencies:
```
sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml pkg-config git
```

2. Install the Go language
> [https://go.dev/doc/install](https://go.dev/doc/install)
>
> The Go binary will be added temporarily to your PATH, to make it permanent append it to your `~/.profile `

3. Clone the Hybrid KEMTLS Go Standard Library repository:
https://github.com/JPADN/go-hybrid-kemtls

4. Run the installation script: `. install.sh`
> You must precisely follow this syntax, in order to execute the script under the current shell
>
> It will clone and compile Liboqs and Liboqs-Go, and compile Hybrid KEMTLS Go
>
> A set of environment variables are going to be set **temporarily**. To make them permanent append the following in your `~/.profile`:
> 
> export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/usr/local/lib
>
> export PKG_CONFIG_PATH=\$PKG_CONFIG_PATH:${PWD}/liboqs-go/.config
>
> export PATH=\${GO_KEMTLS_ROOT}/bin:$PATH
>
>
> Where PWD is this repository root directory and GO_KEMTLS_ROOT is the path to the Hybrid KEMTLS Go stdlib


The resultant Go binary will be used to compile and run the code from this repository
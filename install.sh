#!/bin/bash

# read -p "Path to the Hybrid KEMTLS Go stdlib: "  GO_KEMTLS_ROOT
GO_KEMTLS_ROOT=~/go-kemtls
WORKING_DIR=$PWD

echo "Installing liboqs dependencies..."
sudo apt -y install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml

git clone --branch 0.10.0 https://github.com/open-quantum-safe/liboqs.git 
cd liboqs
mkdir build && cd build
cmake -GNinja -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON ..
sudo ninja
sudo ninja install

cd ${WORKING_DIR}

# Setting LD_LIBRARY_PATH to point to the path to liboqs' library directory, e.g.
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

echo "'/usr/local/lib' was appended temporarily to LD_LIBRARY_PATH, to make it permanent append the following in your ~/.profile:
export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/usr/local/lib
"

git clone --branch 0.10.0  https://github.com/open-quantum-safe/liboqs-go

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${WORKING_DIR}/liboqs-go/.config

echo "'${WORKING_DIR}/liboqs-go/.config' was appended temporarily to PKG_CONFIG_PATH, to make it permanent append the following in your ~/.profile:
export PKG_CONFIG_PATH=\$PKG_CONFIG_PATH:${WORKING_DIR}/liboqs-go/.config
"

wget https://go.dev/dl/go1.22.2.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

cd ${GO_KEMTLS_ROOT}/src
. make.bash

export GO_KEMTLS_ROOT=~/go-kemtls && \
export WORKING_DIR=~/hybrid_kemtls_tests && \
export PATH=${GO_KEMTLS_ROOT}/bin:$PATH && \
echo "
export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/usr/local/lib
export PKG_CONFIG_PATH=\$PKG_CONFIG_PATH:${WORKING_DIR}/liboqs-go/.config
export PATH=${GO_KEMTLS_ROOT}/bin:\$PATH
" | tee -a ~/.bashrc ~/.profile


echo "'${GO_KEMTLS_ROOT}/bin' was appended temporarily to PATH, to make it permanent append the following in your ~/.profile:
export PATH=\${GO_KEMTLS_ROOT}/bin:$PATH
"


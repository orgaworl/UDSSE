<!--
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 16:20:23
-->

## Environment:

### **Required Libraries**

- gmp 6.3 [https://gmplib.org/](https://gmplib.org/)

- openssl 3.0.2 15 [https://www.openssl.org/](https://www.openssl.org/)

- PBC 0.5.4 [https://crypto.stanford.edu/pbc/](https://crypto.stanford.edu/pbc/)

### Install For Ubuntu

```shell
sudo apt install openssl
sudo apt install libgmp-dev
sudo apt install flex
sudo apt install bison
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xzf ./pbc-0.5.14.tar.gz
cd ./pbc-0.5.14
./configure
sudo make
sudo make install
```

## How to compile:

After you huav installed the required libraries, run the command below to compile the program.

```cmake
sh ./compile.sh
```

Then the program will appear in the `bin` folder.

## How to run:

Before you actually run the program, you must run the command below.

```shell
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
```

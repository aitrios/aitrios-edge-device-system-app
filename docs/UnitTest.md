## How to execute UnitTest

### Required environment, tool
* Linux (*)WSL is OK too
* Docker


### Execute UnitTest
1. Execute the following command to run ubuntu:24.04 docker container on Linux PC
``` shell
# On Linux PC
$ cd [The top directory of SystemApp where `LICENSE` file is located]
$ sudo docker run -it --rm -v $(pwd):/host ubuntu:24.04 bash
```

2. Execute the following command to setup the environment on ubuntu:24.04 docker container
``` shell
# On ubuntu:24.04 docker container
$ cd /host/test/script
$ ./env_setup.sh
```
(*)`env_setup.sh` executes apt install, git clone for the UnitTest required code, and so on.

3. Execute the following command to execute UnitTest on ubuntu:24.04 docker container
``` shell
# On ubuntu:24.04 docker container
$ cd /host/test/script
$ ./run_unit_test.sh
```
(*)`run_unit_test.sh` executes build, runs UnitTest and displays coverage rate.

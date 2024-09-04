Step 1: Get a virus total account

Step 2: Get the API key in Virus Total

Step 3: Setup Docker
use this command to download a docker machine
$ docker pull remnux/remnux-distro

check for the installation of the image
$ docker images
REPOSITORY          TAG                 ID                  CREATED             SIZE
ubuntu              12.04               8dbd9e392a96        4 months ago        131.5 MB (virtual 131.5 MB)


step 4: Connect to the docker machine using the command line

There are 2 ways
$ docker exec  -it 30dd348d8907b943d43e168bbab8a8d6ca70b109a289d5975d6d9201eddb6be9 /bin/bash
after -it, put the container id

$ docker run -i -t ubuntu:12.04 /bin/bash
Without a name, just using the ID:
$  docker run -i -t 8dbd9e392a96 /bin/bash

check if the tools we require are installed on the docker machine,
if they are not installed, try to update the machine and save its new
state so that the container will save the new session.

step 5: Now run the Taskmanager.py
This will open a window with all the resource allocation data

step 6: now, select any suspicious files, and open location
This action will create a file named filepath.txt

step7: now run the sandbox.py
This will create a new container and run the file inside
the docker container while caputring the data inside the 
container.


NOTE: The above process will work only when docker network is properly 
configured.

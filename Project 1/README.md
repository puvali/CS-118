# CS118 Project 1

## Makefile

This provides a couple make targets for things.
By default (all target), it makes the `server` executables.

It provides a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Provided Files

`server.c` is the entry points for the server part of the project.

***************************************************************************

NAME: PUVALI CHATTERJEE

UCLA ID: 504822474

HIGH LEVEL DESIGN OF THE SERVER
To establish a server socket, the program creates a socket with the socket
system call and then binds the socket to a server address with the bind
system call. The process then listens for maximum 5 (as permitted by most
systems) connections with the listen syscall and accepts a connection when
it finds a client. It dumps the request message then parses it to find the
requested file.
Depending on whether the file is found, the server sends an appropriate
http response that contains the header lines and requested file to the
client. At any point in the program, if it encounters errors due to
read, write, etc. it prints an error message to standard error and returns
with exit status 1.

PROBLEMS I RAN INTO
I mainly ran into problems while writing code to parse the http request
since there were a lot of details involved in correctly parsing it because
of its specific formatting. I also had trouble figuring out a way to obtain
the name of the requested file and also get the content type from it.
Another issue is that the size of the buffer I used to send the file to the
client is 8192 bytes so when I tried to download royce.jpg, it stalled
because the file is 12.5 MB. I got segmentation faults when I used a bigger
buffer, so I was not able to solve this problem.

ADDITIONAL LIBRARIES USED
The special libraries I used for this program besides stdio.h, unistd.h,
stdlib.h and  string.h are: fcntl.h, dirent.h, netdb.h, netinet/in.h,
sys/types.h, sys/socket.h, sys/stat.h ans sys/wait.h.

OTHER RESOURCES
1. I used the sockets tutorial at
https://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/socket.html
for sample code and a deeper understanding of how sockets work.
2. I used
https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Complete_list_of_MIME_types
for a list of the content type corresponding to each file extension.

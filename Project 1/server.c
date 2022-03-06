#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>

int sockfd, newsockfd;
char *ftype = NULL;
int fd = 0;
struct stat fd_stat;

/*
 ------------------------
|                         |
| error handling function |
|                         |
 -------------------------
*/
void error(char *msg)
{
  perror(msg);
  exit(1);
}

/*
 -----------------------
|                       |
| sets the content type |
|                       |
 -----------------------
*/
void file_type(char* fname)
{
  int fnlen = strlen(fname);
  int e_ind = fnlen - 1;
  char *extn = NULL;
  
  while(fname[e_ind] != '.' && e_ind >= 0)
    {
      e_ind--;
    }

  //no extension, default binary
  if(e_ind == fnlen - 1)
    sprintf(ftype, "application/octet-stream\r\n");

  else
    {
      extn = malloc(sizeof(char) * (fnlen - e_ind));
      memset(extn, 0, sizeof(char) * (fnlen - e_ind));
      strncpy(extn, (fname + e_ind + 1), (fnlen - e_ind - 1));

      if(strcasecmp("txt", extn) == 0)
	sprintf(ftype, "text/plain");

      else if((strcasecmp("html", extn) == 0) ||
	      (strcasecmp("htm", extn) == 0))
	sprintf(ftype, "text/html");

      else if((strcasecmp("jpg", extn) == 0) ||
	  (strcasecmp("jpeg", extn) == 0))
	sprintf(ftype, "image/jpeg");

      else if(strcasecmp("png", extn) == 0)
	sprintf(ftype, "image/png");

      else if(strcasecmp("gif", extn) == 0)
	sprintf(ftype, "image/gif");

      //binary by default
      else
	sprintf(ftype, "application/octet-stream\r\n");
    }
}

/*
 -----------------------------------
|                                   |
| responds to client's http request |
|                                   |
 -----------------------------------
*/
void http_response(char *buf)
{
  //FILENAME PROCESSING
  //request format: GET /filename HTTP/1.1 
  
  char *request = malloc(sizeof(char)*strlen(buf));
  memset(request, 0, sizeof(char)*strlen(buf));
  
  //maximum filename length is 128 characters 
  char *tmp = malloc(sizeof(char)*4096);
  memset(tmp, 0, sizeof(char)*4096);
  char *fname = malloc(sizeof(char)*4096);
  memset(fname, 0, sizeof(char)*4096);

  //global
  ftype = malloc(4096);
  memset(ftype, 0, 4096);

  //finds first instance of \n and overwrites it with \0
  request = strsep(&buf, "\n");

  int i, j;
  //find first space in request
  for(i = 0; i < strlen(request); i++)
    {
      if(request[i] == ' ')
	break;
    }
  //find next space in request
  for(j = strlen(request) - 1; j >= 0; j--)
    {
      if(request[j] == ' ')
	break;
    }

  //copy (j - i - 1) bytes of the string (request + i + 1) to tmp
  strncpy(tmp, (request + i + 1), (j - i - 1));

  //remove / in the beginning
  tmp = tmp + 1;

  //change %20 to spaces in filename and remove
  int m = 0, n = 0;
  while(tmp[m] != '\0')
    {
      if(tmp[m] == '%' && tmp[m+1] == '2' && tmp[m+2] == '0')
	{
	  fname[n] = ' ';
	  m+=3;
	  n++;
	}
      else
	{
	  fname[n] = tmp[m];
	  m++;
	  n++;
	}
    }
  fname[n] = '\0';
  file_type(fname);

  //HTTP RESPONSE
  //HEADERS: STATUS, CONTENT-LENGTH, CONTENT-TYPE

  char respbuf[8192];
  memset(respbuf, 0, 8192);

  char c[1024];
  memset(c, 0, sizeof(char)*1024);
  if(getcwd(c, sizeof(char)*1024) == NULL)
    {
      close(newsockfd);
      close(sockfd);
      error("Could not get cwd\n");
    }

  DIR *currdir = opendir(c);
  struct dirent *ent;
  while((ent = readdir(currdir)) != NULL)
    {
      //found file
      if(strcasecmp(fname, ent->d_name) == 0)
	{
	  fd = open(ent->d_name, O_RDONLY);
	  break;
	}
    }

  if(fd < 0)
    error("Error: unable to open file descriptor\n");

  else if(fd == 0)
      sprintf(respbuf, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nContent-Type: text/html\r\n");
    
  else if(fd > 0)
    {
      fstat(fd, &fd_stat);
      sprintf(respbuf, "HTTP/1.1 200 OK\r\nContent-Length: %lld\r\nContent-Type: %s\r\n", fd_stat.st_size, ftype);
    }

  //print http response
  //printf("%s\n", respbuf);

  //send response
  write(newsockfd, respbuf, strlen(respbuf));

  //send file
  char filebuf[8192];
  memset(filebuf, 0, 8192);
  long nbytes = 0;
  if(fd > 0)
    {
      nbytes = read(fd, filebuf, 8192);     
      if(nbytes >= 0)
	{
	  if(write(newsockfd, filebuf, nbytes) < 0)
	    error("Error writing file to socket\n");
	}
      else
	error("Error reading from socket\n");
    }

  close(fd);
}

/*
 ------
|      |
| main |
|      |
 ------
*/
int main(int argc, char *argv[])
{
  struct sockaddr_in serv_addr, cli_addr;
  socklen_t cli_len;
  int portno;
  int nbytes = 0;
  char req[8192];

  if(argc > 1)
    portno = atoi(argv[1]);
  else
    error("Error: insufficient number of arguments\n");

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0)
    error("Error opening socket\n");

  memset((char *)&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portno);

  if(bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
     error("Error on binding");

  listen(sockfd, 5);

  while(1)
    {
      newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &cli_len);
      if(newsockfd < 0)
	error("Error on accepting\n");

      nbytes = read(newsockfd, req, 8192);
      if(nbytes < 0)
	{
	  close(sockfd);
	  close(newsockfd);
	  error("Error reading from client socket\n");
	}

      printf("%s\n", req);
      http_response(req);
    }
  
  return 0;
}

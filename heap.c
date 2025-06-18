#include "stdlib.h"
#include "stdio.h"
#include "string.h"
int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0); 

	char *buffer = (char *)malloc(100);
	char *datafile = (char *)malloc(20);

	strcpy(datafile, "/var/nodes");
	strcpy(buffer, argv[1]);

	printf("[DEBUG] buffer: @ %p: \ '%s\' \n", buffer, buffer);

	printf("[DEBUG] datafile @ %p: \ '%s\' \n", datafile, datafile);

	free(buffer);
	free(datafile);

}
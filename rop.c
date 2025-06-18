#include "stdio.h" 
#include "string.h" 
 
char* mycmd = "cat ./secretfile.txt"; 
 
void intermedia_code() {     
    printf("Not a secret\n");     
    system("/bin/date"); 
} 
 
void vulnerable_function(char* string) {     
    char buffer[9]; 
    strcpy(buffer, string); 
} 
 
int main(int argc, char** argv) {     
    vulnerable_function(argv[1]);     
    return 0; 
} 

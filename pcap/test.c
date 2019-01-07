
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "pcap.h"

int main(int argc, char* argv[]) {
    //const char* fname = "icmp.log";
    char* fname;
    uint8_t* buf = NULL;
    struct stat st;

    if (argc < 2) {
        printf("usage.. test filename\n");
        exit(1);
    }
    fname = argv[1];



    stat(fname, &st);
    printf("size = %d\n", (int)st.st_size);
    buf = (uint8_t*)malloc(st.st_size);

    int fp = open(fname, O_RDONLY);
    if (fp < 0) {
        exit(1);
    }
    read(fp, buf, st.st_size);
    analyze_packet(buf, st.st_size);
    close(fp);


    free(buf);
    return 0;
}

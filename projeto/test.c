#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *file = fopen("tcp_buffer.txt", "rb");
    FILE *dest = fopen("dest.jpg", "wb");
    char a[100], b[100], c[100], d[100], e[100], f[100], g[110];
    fscanf(file,"%s%s%s%s%s%s%s", a,b,c,d,e,f,g);
    fseek(file,1,SEEK_CUR);
    printf("%s\n", f);
    ssize_t bytes_written;
    char buffer[1024];
    long bytes_left = 8844;
    while (bytes_left > 0) {
        ssize_t bytes_read = fread(buffer, 1, 1024, file);
        bytes_left -= bytes_read;
        char *buffer_ptr = buffer;
        while (bytes_read > 0) {
            bytes_written = fwrite(buffer_ptr, 1, 1024, dest);
            if (bytes_written <= 0)
                exit(1);
            bytes_read -= bytes_written;
            buffer_ptr += bytes_written;
        }
    }
    fclose(file);
}

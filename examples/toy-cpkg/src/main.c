#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Example-only parser used to exercise the audit pipeline. */
static int parse_record(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    char name[16];
    unsigned char len = 0;
    if (fread(&len, 1, 1, fp) != 1) {
        fclose(fp);
        return 1;
    }

    char *tmp = (char *)malloc(len + 1);
    if (tmp == NULL) {
        fclose(fp);
        return 1;
    }
    if (fread(tmp, 1, len, fp) != len) {
        free(tmp);
        fclose(fp);
        return 1;
    }
    tmp[len] = '\0';

    /* Deliberately unsafe example: file-controlled length reaches strcpy. */
    strcpy(name, tmp);
    printf("record=%s\n", name);

    free(tmp);
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <record-file>\n", argv[0]);
        return 2;
    }
    return parse_record(argv[1]);
}

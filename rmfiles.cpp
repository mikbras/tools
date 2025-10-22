#include <cstdio>
#include <cstdlib>
#include <climits>
#include <cctype>
#include <cstring>
#include <unistd.h>

using namespace std;

const char* arg0;

#define USAGE "Usage: %s <filelist-filename>\n"

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    FILE* stream;
    char line[PATH_MAX+2];

    if (argc != 2)
    {
        fprintf(stderr, USAGE, arg0);
        exit(1);
    }

    const char* filename = argv[1];

    if (!(stream = fopen(filename, "rb")))
    {
        fprintf(stderr, "%s: cannot open: %s\n", arg0, filename);
        exit(1);
    }

    while(fgets(line, sizeof(line), stream) != NULL)
    {
        char* p = line + strlen(line);

        while (p != line && isspace(p[-1]))
            *--p = '\0';

        printf("line{%s}\n", line);

        if (unlink(line) < 0)
        {
            fprintf(stderr, "%s: failed to remove: %s\n", arg0, line);
            exit(1);
        }
    }

    fclose(stream);

    return 0;
}

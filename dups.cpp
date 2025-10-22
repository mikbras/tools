#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cstdint>
#include <map>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <lzma.h>
#include <sys/stat.h>
#include <vector>
#if 0
#include <openssl/sha.h>
#endif
#include <unordered_map>

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

using namespace std;

const char* arg0;

typedef struct
{
    union
    {
        uint8_t buf[32];
        uint64_t words[4];
    };
}
sha256_t;

static_assert(sizeof(sha256_t) == 32);

inline bool operator==(const sha256_t& x, const sha256_t& y)
{
    return
        x.words[0] == y.words[0] &&
        x.words[1] == y.words[1] &&
        x.words[2] == y.words[2] &&
        x.words[3] == y.words[3];
}

struct HashFunc
{
    std::size_t operator()(const sha256_t& h) const
    {
        return h.words[0] ^ h.words[1] ^ h.words[2] ^ h.words[3];
    }
};

typedef unordered_map<uint32_t, string> Map;
typedef pair<uint32_t, string> Pair;

class Context
{
public:
    bool opt_hard_links;
    bool opt_identical;

    size_t min_size;
    FILE* stream;
    size_t bytes;
    size_t num_duplicates;
    size_t num_collisions;
    Map map;
    vector<pair<string,string>> hard_links;

    Context() :
        opt_hard_links(false),
        opt_identical(false),
        min_size(0),
        stream(nullptr),
        bytes(0),
        num_duplicates(0),
        num_collisions(0)
    {
    }
};

#if 0
static int _compute_partial_file_hash(
    const string& path,
    size_t filesize,
    sha256_t& hash)
{
    int ret = 0;
    int fd = -1;
    char buf[4096];
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &filesize, sizeof(filesize));

    if ((fd = open(path.c_str(), O_RDONLY, 0)) < 0)
    {
        ret = errno;
        goto done;
    }

    for (;;)
    {
        ssize_t n = read(fd, buf, sizeof(buf));

        if (n < 0)
        {
            ret = errno;
            goto done;
        }

        if (n == 0)
            break;

        SHA256_Update(&ctx, buf, n);
        break;
    }

    SHA256_Final(hash.buf, &ctx);

done:

    if (fd >= 0)
        close(fd);

    return ret;
}
#endif

static int _compute_partial_file_crc(
    const string& path,
    size_t filesize,
    uint32_t& crc)
{
    int ret = 0;
    int fd = -1;
    uint8_t buf[BUFSIZ];

    crc = lzma_crc32((const uint8_t*)&filesize, sizeof(filesize), 0);

    if ((fd = open(path.c_str(), O_RDONLY, 0)) < 0)
    {
        ret = errno;
        goto done;
    }

    for (;;)
    {
        ssize_t n = read(fd, buf, sizeof(buf));

        if (n < 0)
        {
            ret = errno;
            goto done;
        }

        if (n == 0)
            break;

        crc = lzma_crc32((uint8_t*)buf, n, crc);
        break;
    }

done:

    if (fd >= 0)
        close(fd);

    return ret;
}

#if 0
static int _compute_file_hash(const string& path, sha256_t& hash)
{
    int ret = 0;
    int fd = -1;
    char buf[BUFSIZ];
    SHA256_CTX ctx;

    SHA256_Init(&ctx);

    if ((fd = open(path.c_str(), O_RDONLY, 0)) < 0)
    {
        ret = errno;
        goto done;
    }

    for (;;)
    {
        ssize_t n = read(fd, buf, sizeof(buf));

        if (n < 0)
        {
            ret = errno;
            goto done;
        }

        if (n == 0)
            break;

        SHA256_Update(&ctx, buf, n);
    }

    SHA256_Final(hash.buf, &ctx);

done:

    if (fd >= 0)
        close(fd);

    return ret;
}
#endif

static int _compare_files(const string& path1, const string& path2)
{
    int ret = 0;
    FILE* stream1 = NULL;
    FILE* stream2 = NULL;
    const size_t BUFFER_SIZE = 4096;
    uint8_t buf1[BUFFER_SIZE];
    uint8_t buf2[BUFFER_SIZE];


    if (!(stream1 = fopen(path1.c_str(), "rb")))
    {
        ret = -ENOENT;
        goto done;
    }

    if (!(stream2 = fopen(path2.c_str(), "rb")))
    {
        ret = -ENOENT;
        goto done;
    }

    for (;;)
    {
        ssize_t n1 = fread(buf1, 1, BUFFER_SIZE, stream1);
        ssize_t n2 = fread(buf2, 1, BUFFER_SIZE, stream2);

        if (n1 != n2)
        {
            ret = -ENOENT;
            goto done;
        }

        if (n1 == 0)
        {
            // Files are identical
            break;
        }

        if (memcmp(buf1, buf2, n1) != 0)
        {
            ret = -ENOENT;
            goto done;
        }
    }

done:

    if (stream1)
        fclose(stream1);

    if (stream2)
        fclose(stream2);

    return ret;
}

static void _log_duplicates(
    FILE* stream,
    const string& path1,
    const string& path2)
{
    fprintf(stream, "< %s\n", path1.c_str());
    fprintf(stream, "> %s\n", path2.c_str());
    fprintf(stream, "\n");
    fflush(stream);
}

static void _log_identicals(
    FILE* stream,
    const string& path1,
    const string& path2)
{
    fprintf(stream, "[ %s\n", path1.c_str());
    fprintf(stream, "] %s\n", path2.c_str());
    fprintf(stream, "\n");
    fflush(stream);
}

static void _log_summary(const Context& c, FILE* stream)
{
    const double GIGABYTE = (1024 * 1024 * 1024);
    fprintf(stream, "Duplicates: %zu\n", c.num_duplicates);
    fprintf(stream, "Collisions: %zu\n", c.num_collisions);
    fprintf(stream, "Duplicate space: %.3lfG\n", c.bytes / GIGABYTE);
}

static int _search(Context& c, const string& path)
{
    DIR* dir;
    struct dirent* ent;
    vector<string> dirs;

    if (!(dir = opendir(path.c_str())))
    {
        return 0;
    }

    while ((ent = readdir(dir)))
    {
        const string name = ent->d_name;
        struct stat statbuf;

        if (name == "." || name == "..")
            continue;

        const string fullname = path + "/" + name;

        if (lstat(fullname.c_str(), &statbuf) < 0)
        {
            fprintf(stderr, "%s: stat failed: %s\n", arg0, fullname.c_str());
            exit(1);
        }

        if (S_ISDIR(statbuf.st_mode))
        {
            dirs.push_back(fullname);
        }
        else if (S_ISREG(statbuf.st_mode))
        {
            uint32_t crc;
            const size_t size = statbuf.st_size;

            // Skip zero-sized files
            if (size == 0)
                continue;

            if (size <= c.min_size)
                continue;

            if (_compute_partial_file_crc(fullname.c_str(), size, crc) < 0)
            {
                fprintf(stderr, "%s: crc computation failed: %s\n",
                    arg0, fullname.c_str());
                exit(1);
            }

            Map::const_iterator p = c.map.find(crc);

            if (p != c.map.end())
            {
                const string cached_fullname = (*p).second;
                struct stat cached_statbuf;

                if (lstat(cached_fullname.c_str(), &cached_statbuf) < 0)
                {
                    fprintf(stderr, "%s: stat failed: %s\n",
                        arg0, cached_fullname.c_str());
                    exit(1);
                }

                if (cached_statbuf.st_ino == statbuf.st_ino)
                {
                    if (c.opt_identical)
                    {
                        _log_identicals(c.stream, cached_fullname, fullname);
                        _log_identicals(stdout, cached_fullname, fullname);
                    }
                }
                else
                {
                    if (_compare_files(cached_fullname, fullname) == 0)
                    {
                        c.bytes += size;
                        _log_duplicates(stdout, cached_fullname, fullname);
                        _log_duplicates(c.stream, cached_fullname, fullname);

                        if (c.opt_hard_links)
                        {
                            c.hard_links.push_back(
                                pair<string,string>(cached_fullname, fullname));
                        }

                        c.num_duplicates++;
                    }
                    else
                    {
                        c.num_collisions++;
                    }
                }
            }
            else
            {
                // Only add file with this CRC once
                c.map.insert(Pair(crc, fullname));
            }
        }
        else
        {
            // Skip other file types
            continue;
        }
    }

    closedir(dir);

    for (size_t i = 0; i < dirs.size(); i++)
    {
        _search(c, dirs[i]);
    }

    return 0;
}

#define USAGE "\
Usage: %s [-m min-size | -h] <dirname>...\n\
\n\
Options:\n\
    -m min-size         -- consider only files greater than min-size\n\
    -h                  -- replace duplicate files with hard links\n\
    -i                  -- show identical files\n\
\n\
"

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    Map map;
    const char dups_log[] = "dups.log";
    FILE* stream;
    Context c;
    int opt;

    while ((opt = getopt(argc, (char**)argv, "ihm:")) != -1)
    {
        switch (opt)
        {
            case 'm':
            {
                const char* arg = optarg;
                size_t len = strlen(arg);

                if (len == 0)
                {
                    fprintf(stderr, "%s: bad -m arg\n", arg0);
                    exit(0);
                }

                if (arg[len-1] == 'M')
                {
                    const char* p = &arg[len-1];
                    char* end = NULL;
                    c.min_size = strtoul(arg, &end, 10);

                    if (!end || end != p)
                    {
                        fprintf(stderr, "%s: bad -m arg\n", arg0);
                        exit(0);
                    }

                    c.min_size *= 1024 * 1024;
                }
                else
                {
                    char* end = NULL;
                    c.min_size = strtoul(arg, &end, 10);

                    if (!end || *end)
                    {
                        fprintf(stderr, "%s: bad -m arg\n", arg0);
                        exit(0);
                    }
                }

                break;
            }
            case 'h':
            {
                c.opt_hard_links = true;
                break;
            }
            case 'i':
            {
                c.opt_identical = true;
                break;
            }
            default:
            {
                fprintf(stderr, USAGE, arg0);
                exit(1);
            }
        }
    }

    if (argc < 2)
    {
        fprintf(stderr, USAGE, arg0);
        exit(1);
    }

    if (!(stream = fopen(dups_log, "wb")))
    {
        fprintf(stderr, "%s: cannot open: %s\n", arg0, dups_log);
        exit(1);
    }

    c.stream = stream;
    //c.min_size = 1024*1024;

    for (int i = 1; i < argc; i++)
        _search(c, argv[i]);

    if (c.opt_hard_links)
    {
        fprintf(c.stream, "Unlinking %zu files...\n", c.hard_links.size());
        fprintf(stdout, "Unlinking %zu files...\n", c.hard_links.size());

        for (size_t i = 0; i < c.hard_links.size(); i++)
        {
            string first = c.hard_links[i].first;
            string second = c.hard_links[i].second;

            //printf("unlink %s\n", second.c_str());

            if (unlink(second.c_str()) < 0)
            {
                fprintf(stderr, "%s: unlink failed: %s\n",
                    arg0, second.c_str());
                exit(1);
            }

            //printf("link %s %s\n", first.c_str(), second.c_str());

            if (link(first.c_str(), second.c_str()) < 0)
            {
                fprintf(stderr, "%s: unlink failed: %s\n", arg0, first.c_str());
                exit(1);
            }
        }
    }

    _log_summary(c, stdout);
    _log_summary(c, c.stream);
    fclose(stream);

    return 0;
}

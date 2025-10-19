#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cstdint>
#include <map>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <vector>
#include <openssl/sha.h>
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

typedef unordered_map<sha256_t, string, HashFunc> Map;
typedef pair<sha256_t, string> Pair;

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

static int _compute_full_file_hash(
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
    }

    SHA256_Final(hash.buf, &ctx);

done:

    if (fd >= 0)
        close(fd);

    return ret;
}

static int _search(Map& map, const string& path)
{
    DIR* dir;
    struct dirent* ent;
    vector<string> dirs;

    if (!(dir = opendir(path.c_str())))
    {
        //fprintf(stderr, "%s: warning: opendir() failed: %s\n", arg0, path.c_str());
        return 0;
        //exit(1);
    }

    while ((ent = readdir(dir)))
    {
        string name = ent->d_name;
        struct stat statbuf;
        sha256_t hash;

        if (name == "." || name == "..")
            continue;

        const string fullname = path + "/" + name;

        if (stat(fullname.c_str(), &statbuf) < 0)
        {
            fprintf(stderr, "%s: stat failed: %s\n", arg0, fullname.c_str());
            exit(1);
        }

        // Skip zero-sized files
        if (statbuf.st_size == 0)
            continue;

        if ((statbuf.st_mode & S_IFMT) == S_IFDIR)
            dirs.push_back(fullname);
        else
        {
            if (_compute_partial_file_hash(fullname.c_str(), statbuf.st_size, hash) < 0)
            {
                fprintf(stderr, "%s: hash failed: %s\n", arg0, fullname.c_str());
                exit(1);
            }

            Map::const_iterator p = map.find(hash);

            if (p != map.end())
            {
                const string fullname2 = (*p).second;
                struct stat statbuf2;

                if (stat(fullname2.c_str(), &statbuf2) < 0)
                {
                    fprintf(stderr, "%s: stat failed: %s\n", arg0, fullname2.c_str());
                    exit(1);
                }

                if (statbuf.st_size == statbuf2.st_size)
                {
                    sha256_t fullhash1;
                    sha256_t fullhash2;

                    if (_compute_full_file_hash(
                        fullname.c_str(), statbuf.st_size, fullhash1) < 0)
                    {
                        fprintf(stderr, "%s: hash failed: %s\n",
                            arg0, fullname.c_str());
                        exit(1);
                    }

                    if (_compute_full_file_hash(
                        fullname2.c_str(), statbuf2.st_size, fullhash2) < 0)
                    {
                        fprintf(stderr, "%s: hash failed: %s\n",
                            arg0, fullname2.c_str());
                        exit(1);
                    }

                    if (fullhash1 == fullhash2)
                    {
                        printf("%s:%s\n", fullname2.c_str(), fullname.c_str());
                    }
                }
            }

            map.insert(Pair(hash, fullname));
        }
    }

    closedir(dir);

    for (size_t i = 0; i < dirs.size(); i++)
    {
        _search(map, dirs[i]);
    }

    return 0;
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    Map map;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <dirname>\n", arg0);
        exit(1);
    }

    _search(map, argv[1]);

    return 0;
}

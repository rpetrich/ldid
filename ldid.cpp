/* JocStrap - Java/Objective-C Bootstrap
 * Copyright (C) 2007  Jay Freeman (saurik)
*/

/*
 *        Redistribution and use in source and binary
 * forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the
 *    above copyright notice, this list of conditions
 *    and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the
 *    above copyright notice, this list of conditions
 *    and the following disclaimer in the documentation
 *    and/or other materials provided with the
 *    distribution.
 * 3. The name of the author may not be used to endorse
 *    or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "minimal/stdlib.h"
#include "minimal/mapping.h"

#include <cstring>
#include <string>
#include <vector>

struct fat_header {
    uint32_t magic;
    uint32_t nfat_arch;
};

#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca

struct fat_arch {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

struct mach_header {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

#define	MH_MAGIC 0xfeedface
#define MH_CIGAM 0xcefaedfe

#define	MH_EXECUTE 0x2
#define	MH_DYLIB   0x6
#define	MH_BUNDLE  0x8

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

#define LC_REQ_DYLD  0x80000000

#define	LC_LOAD_DYLIB	   0x0c
#define	LC_ID_DYLIB	   0x0d
#define LC_UUID		   0x1b
#define LC_REEXPORT_DYLIB (0x1f | LC_REQ_DYLD)

struct dylib {
    uint32_t name;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
};

struct dylib_command {
    uint32_t cmd;
    uint32_t cmdsize;
    struct dylib dylib;
};

struct uuid_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t uuid[16];
};

class Framework {
  private:
    void *base_;
    size_t size_;
    mach_header *mach_header_;
    bool swapped_;

  public:
    int16_t Swap(int16_t value) const {
        return Swap(static_cast<uint16_t>(value));
    }

    int32_t Swap(int32_t value) const {
        return Swap(static_cast<uint32_t>(value));
    }

    uint16_t Swap(uint16_t value) const {
        return !swapped_ ? value :
            ((value >>  8) & 0x00ff) |
            ((value <<  8) & 0xff00);
    }

    uint32_t Swap(uint32_t value) const {
        if (!swapped_)
            return value;
        else {
            value = ((value >>  8) & 0x00ff00ff) |
                    ((value <<  8) & 0xff00ff00);
            value = ((value >> 16) & 0x0000ffff) |
                    ((value << 16) & 0xffff0000);
            return value;
        }
    }

    Framework(const char *framework_path) :
        swapped_(false)
    {
        base_ = map(framework_path, 0, _not(size_t), &size_, false);
        fat_header *fat_header = reinterpret_cast<struct fat_header *>(base_);

        if (Swap(fat_header->magic) == FAT_CIGAM) {
            swapped_ = !swapped_;
            goto fat;
        } else if (Swap(fat_header->magic) != FAT_MAGIC)
            mach_header_ = (mach_header *) base_;
        else fat: {
            size_t fat_narch = Swap(fat_header->nfat_arch);
            fat_arch *fat_arch = reinterpret_cast<struct fat_arch *>(fat_header + 1);
            size_t arch;
            for (arch = 0; arch != fat_narch; ++arch) {
                uint32_t arch_offset = Swap(fat_arch->offset);
                mach_header_ = (mach_header *) ((uint8_t *) base_ + arch_offset);
                goto found;
                ++fat_arch;
            }

            _assert(false);
        }

      found:
        if (Swap(mach_header_->magic) == MH_CIGAM)
            swapped_ = !swapped_;
        else _assert(Swap(mach_header_->magic) == MH_MAGIC);

        _assert(
            Swap(mach_header_->filetype) == MH_EXECUTE ||
            Swap(mach_header_->filetype) == MH_DYLIB ||
            Swap(mach_header_->filetype) == MH_BUNDLE
        );
    }

    void *GetBase() {
        return base_;
    }

    size_t GetSize() {
        return size_;
    }

    std::vector<struct load_command *> GetLoadCommands() {
        std::vector<struct load_command *> load_commands;

        struct load_command *load_command = reinterpret_cast<struct load_command *>(mach_header_ + 1);
        for (uint32_t cmd = 0; cmd != Swap(mach_header_->ncmds); ++cmd) {
            load_commands.push_back(load_command);
            load_command = (struct load_command *) ((uint8_t *) load_command + Swap(load_command->cmdsize));
        }

        return load_commands;
    }
};

extern "C" uint32_t hash(uint8_t *k, uint32_t length, uint32_t initval);

int main(int argc, const char *argv[]) {
    bool flag_R(false);
    bool flag_t(false);
    bool flag_p(false);
    bool flag_u(false);

    bool flag_T(false);

    bool timeh(false);
    uint32_t timev(0);

    std::vector<std::string> files;

    _assert(argc != 0);
    for (int argi(1); argi != argc; ++argi)
        if (argv[argi][0] != '-')
            files.push_back(argv[argi]);
        else switch (argv[argi][1]) {
            case 'R': flag_R = true; break;
            case 't': flag_t = true; break;
            case 'u': flag_u = true; break;
            case 'p': flag_p = true; break;

            case 'T': {
                flag_T = true;
                if (argv[argi][2] == '-')
                    timeh = true;
                else {
                    char *arge;
                    timev = strtoul(argv[argi] + 2, &arge, 0);
                    _assert(arge == argv[argi] + strlen(argv[argi]));
                }
            } break;

            default:
                goto usage;
            break;
        }

    if (files.empty()) usage: {
        exit(0);
    }

    size_t filei(0), filee(0);
    _foreach (file, files) try {
        Framework framework(file->c_str());

        if (flag_p)
            printf("path%zu='%s'\n", filei, file->c_str());

        _foreach (load_command, framework.GetLoadCommands()) {
            uint32_t cmd(framework.Swap((*load_command)->cmd));

            if (flag_R && cmd == LC_REEXPORT_DYLIB)
                (*load_command)->cmd = framework.Swap(LC_LOAD_DYLIB);
            else if (cmd == LC_UUID) {
                volatile struct uuid_command *uuid_command(reinterpret_cast<struct uuid_command *>(*load_command));

                if (flag_u) {
                    printf("uuid%zu=%.2x%.2x%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x%.2x%.2x%.2x%.2x\n", filei,
                        uuid_command->uuid[ 0], uuid_command->uuid[ 1], uuid_command->uuid[ 2], uuid_command->uuid[ 3],
                        uuid_command->uuid[ 4], uuid_command->uuid[ 5], uuid_command->uuid[ 6], uuid_command->uuid[ 7],
                        uuid_command->uuid[ 8], uuid_command->uuid[ 9], uuid_command->uuid[10], uuid_command->uuid[11],
                        uuid_command->uuid[12], uuid_command->uuid[13], uuid_command->uuid[14], uuid_command->uuid[15]
                    );
                }
            } else if (cmd == LC_ID_DYLIB) {
                volatile struct dylib_command *dylib_command(reinterpret_cast<struct dylib_command *>(*load_command));

                if (flag_t)
                    printf("time%zu=0x%.8x\n", filei, framework.Swap(dylib_command->dylib.timestamp));

                if (flag_T) {
                    uint32_t timed;

                    if (!timeh)
                        timed = timev;
                    else {
                        dylib_command->dylib.timestamp = 0;
                        timed = hash(reinterpret_cast<uint8_t *>(framework.GetBase()), framework.GetSize(), timev);
                    }

                    dylib_command->dylib.timestamp = framework.Swap(timed);
                }
            }
        }

        ++filei;
    } catch (const char *) {
        ++filee;
        ++filei;
    }

    return filee;
}

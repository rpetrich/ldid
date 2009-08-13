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
#include "minimal/string.h"
#include "minimal/mapping.h"

#include "sha1.h"

#include <cstring>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

struct fat_header {
    uint32_t magic;
    uint32_t nfat_arch;
} _packed;

#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca

struct fat_arch {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
} _packed;

struct mach_header {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
} _packed;

#define MH_MAGIC 0xfeedface
#define MH_CIGAM 0xcefaedfe

#define MH_DYLDLINK   0x4

#define MH_EXECUTE    0x2
#define MH_DYLIB      0x6
#define MH_BUNDLE     0x8
#define MH_DYLIB_STUB 0x9

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
} _packed;

#define LC_REQ_DYLD  uint32_t(0x80000000)

#define	LC_SEGMENT         uint32_t(0x01)
#define LC_LOAD_DYLIB      uint32_t(0x0c)
#define LC_ID_DYLIB        uint32_t(0x0d)
#define LC_UUID            uint32_t(0x1b)
#define LC_CODE_SIGNATURE  uint32_t(0x1d)
#define LC_REEXPORT_DYLIB  uint32_t(0x1f | LC_REQ_DYLD)

struct dylib {
    uint32_t name;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
} _packed;

struct dylib_command {
    uint32_t cmd;
    uint32_t cmdsize;
    struct dylib dylib;
} _packed;

struct uuid_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t uuid[16];
} _packed;

struct segment_command {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section {
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
};

struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
} _packed;

uint16_t Swap_(uint16_t value) {
    return
        ((value >>  8) & 0x00ff) |
        ((value <<  8) & 0xff00);
}

uint32_t Swap_(uint32_t value) {
    value = ((value >>  8) & 0x00ff00ff) |
            ((value <<  8) & 0xff00ff00);
    value = ((value >> 16) & 0x0000ffff) |
            ((value << 16) & 0xffff0000);
    return value;
}

int16_t Swap_(int16_t value) {
    return Swap_(static_cast<uint16_t>(value));
}

int32_t Swap_(int32_t value) {
    return Swap_(static_cast<uint32_t>(value));
}

uint16_t Swap(uint16_t value) {
    return true ? Swap_(value) : value;
}

uint32_t Swap(uint32_t value) {
    return true ? Swap_(value) : value;
}

int16_t Swap(int16_t value) {
    return Swap(static_cast<uint16_t>(value));
}

int32_t Swap(int32_t value) {
    return Swap(static_cast<uint32_t>(value));
}

template <typename Target_>
class Pointer;

class Framework {
  private:
    void *base_;
    size_t size_;
    mach_header *mach_header_;
    bool swapped_;

  public:
    uint16_t Swap(uint16_t value) const {
        return swapped_ ? Swap_(value) : value;
    }

    uint32_t Swap(uint32_t value) const {
        return swapped_ ? Swap_(value) : value;
    }

    int16_t Swap(int16_t value) const {
        return Swap(static_cast<uint16_t>(value));
    }

    int32_t Swap(int32_t value) const {
        return Swap(static_cast<uint32_t>(value));
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

    struct mach_header *operator ->() const {
        return mach_header_;
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

    std::vector<segment_command *> GetSegments(const char *segment_name) {
        std::vector<struct segment_command *> segment_commands;

        _foreach (load_command, GetLoadCommands())
            if (Swap((*load_command)->cmd) == LC_SEGMENT) {
                segment_command *segment_command = reinterpret_cast<struct segment_command *>(*load_command);
                if (strncmp(segment_command->segname, segment_name, 16) == 0)
                    segment_commands.push_back(segment_command);
            }

        return segment_commands;
    }

    std::vector<section *> GetSections(const char *segment_name, const char *section_name) {
        std::vector<section *> sections;

        _foreach (segment, GetSegments(segment_name)) {
            section *section = (struct section *) (*segment + 1);

            uint32_t sect;
            for (sect = 0; sect != Swap((*segment)->nsects); ++sect) {
                if (strncmp(section->sectname, section_name, 16) == 0)
                    sections.push_back(section);
                ++section;
            }
        }

        return sections;
    }

    template <typename Target_>
    Pointer<Target_> GetPointer(uint32_t address, const char *segment_name = NULL) {
        load_command *load_command = (struct load_command *) (mach_header_ + 1);
        uint32_t cmd;

        for (cmd = 0; cmd != Swap(mach_header_->ncmds); ++cmd) {
            if (Swap(load_command->cmd) == LC_SEGMENT) {
                segment_command *segment_command = (struct segment_command *) load_command;
                if (segment_name != NULL && strncmp(segment_command->segname, segment_name, 16) != 0)
                    goto next_command;

                section *sections = (struct section *) (segment_command + 1);

                uint32_t sect;
                for (sect = 0; sect != Swap(segment_command->nsects); ++sect) {
                    section *section = &sections[sect];
                    //printf("%s %u %p %p %u\n", segment_command->segname, sect, address, section->addr, section->size);
                    if (address >= Swap(section->addr) && address < Swap(section->addr) + Swap(section->size)) {
                        //printf("0x%.8x %s\n", address, segment_command->segname);
                        return Pointer<Target_>(this, reinterpret_cast<Target_ *>(address - Swap(section->addr) + Swap(section->offset) + (char *) mach_header_));
                    }
                }
            }

          next_command:
            load_command = (struct load_command *) ((char *) load_command + Swap(load_command->cmdsize));
        }

        return Pointer<Target_>(this);
    }

    template <typename Target_>
    Pointer<Target_> GetOffset(uint32_t offset) {
        return Pointer<Target_>(this, reinterpret_cast<Target_ *>(offset + (uint8_t *) mach_header_));
    }
};

template <typename Target_>
class Pointer {
  private:
    const Framework *framework_;
    const Target_ *pointer_;

  public:
    Pointer(const Framework *framework = NULL, const Target_ *pointer = NULL) :
        framework_(framework),
        pointer_(pointer)
    {
    }

    operator const Target_ *() const {
        return pointer_;
    }

    const Target_ *operator ->() const {
        return pointer_;
    }

    Pointer<Target_> &operator ++() {
        ++pointer_;
        return *this;
    }

    template <typename Value_>
    Value_ Swap(Value_ value) {
        return framework_->Swap(value);
    }
};

#define CSMAGIC_CODEDIRECTORY      uint32_t(0xfade0c02)
#define CSMAGIC_EMBEDDED_SIGNATURE uint32_t(0xfade0cc0)
#define CSMAGIC_ENTITLEMENTS       uint32_t(0xfade7171)

#define CSSLOT_CODEDIRECTORY uint32_t(0)
#define CSSLOT_REQUIREMENTS  uint32_t(2)
#define CSSLOT_ENTITLEMENTS  uint32_t(5)

struct BlobIndex {
    uint32_t type;
    uint32_t offset;
} _packed;

struct Blob {
    uint32_t magic;
    uint32_t length;
} _packed;

struct SuperBlob {
    struct Blob blob;
    uint32_t count;
    struct BlobIndex index[];
} _packed;

struct CodeDirectory {
    struct Blob blob;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t hashSize;
    uint8_t hashType;
    uint8_t spare1;
    uint8_t pageSize;
    uint32_t spare2;
} _packed;

extern "C" uint32_t hash(uint8_t *k, uint32_t length, uint32_t initval);

#define CODESIGN_ALLOCATE "arm-apple-darwin9-codesign_allocate"

void sha1(uint8_t *hash, uint8_t *data, size_t size) {
    SHA1Context context;
    SHA1Reset(&context);
    SHA1Input(&context, data, size);
    SHA1Result(&context, hash);
}

int main(int argc, const char *argv[]) {
    bool flag_R(false);
    bool flag_t(false);
    bool flag_p(false);
    bool flag_u(false);
    bool flag_e(false);

    bool flag_T(false);

    bool flag_S(false);
    bool flag_s(false);

    bool timeh(false);
    uint32_t timev(0);

    const void *xmld(NULL);
    size_t xmls(0);

    uintptr_t noffset(_not(uintptr_t));
    uintptr_t woffset(_not(uintptr_t));

    std::vector<std::string> files;

    if (argc == 1) {
        fprintf(stderr, "usage: %s -S[entitlements.xml] <binary>\n", argv[0]);
        fprintf(stderr, "   %s -e MobileSafari\n", argv[0]);
        fprintf(stderr, "   %s -S cat\n", argv[0]);
        fprintf(stderr, "   %s -Stfp.xml gdb\n", argv[0]);
        exit(0);
    }

    for (int argi(1); argi != argc; ++argi)
        if (argv[argi][0] != '-')
            files.push_back(argv[argi]);
        else switch (argv[argi][1]) {
            case 'R': flag_R = true; break;
            case 't': flag_t = true; break;
            case 'u': flag_u = true; break;
            case 'p': flag_p = true; break;
            case 'e': flag_e = true; break;

            case 's':
                _assert(!flag_S);
                flag_s = true;
            break;

            case 'S':
                _assert(!flag_s);
                flag_S = true;
                if (argv[argi][2] != '\0') {
                    const char *xml = argv[argi] + 2;
                    xmld = map(xml, 0, _not(size_t), &xmls, true);
                }
            break;

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

            case 'n': {
                char *arge;
                noffset = strtoul(argv[argi] + 2, &arge, 0);
                _assert(arge == argv[argi] + strlen(argv[argi]));
            } break;

            case 'w': {
                char *arge;
                woffset = strtoul(argv[argi] + 2, &arge, 0);
                _assert(arge == argv[argi] + strlen(argv[argi]));
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
        const char *path(file->c_str());
        const char *base = strrchr(path, '/');
        char *temp(NULL), *dir;

        if (base != NULL)
            dir = strndup_(path, base++ - path + 1);
        else {
            dir = strdup("");
            base = path;
        }

        if (flag_S) {
            asprintf(&temp, "%s.%s.cs", dir, base);
            const char *allocate = getenv("CODESIGN_ALLOCATE");
            if (allocate == NULL)
                allocate = "codesign_allocate";

            size_t size = _not(size_t);
            const char *arch; {
                Framework framework(path);
                framework->flags |= MH_DYLDLINK;

                _foreach (load_command, framework.GetLoadCommands()) {
                    uint32_t cmd(framework.Swap((*load_command)->cmd));
                    if (cmd == LC_CODE_SIGNATURE) {
                        struct linkedit_data_command *signature = reinterpret_cast<struct linkedit_data_command *>(*load_command);
                        size = framework.Swap(signature->dataoff);
                        _assert(size < framework.GetSize());
                        break;
                    }
                }

                if (size == _not(size_t))
                    size = framework.GetSize();

                switch (framework->cputype) {
                    case 12: switch (framework->cpusubtype) {
                        case 0: arch = "arm"; break;
                        case 6: arch = "armv6"; break;
                        default: arch = NULL; break;
                    } break;

                    default: arch = NULL; break;
                }
            }

            _assert(arch != NULL);

            pid_t pid = fork();
            _syscall(pid);
            if (pid == 0) {
                char *ssize;
                asprintf(&ssize, "%u", (sizeof(struct SuperBlob) + 2 * sizeof(struct BlobIndex) + sizeof(struct CodeDirectory) + strlen(base) + 1 + ((xmld == NULL ? CSSLOT_REQUIREMENTS : CSSLOT_ENTITLEMENTS) + (size + 0x1000 - 1) / 0x1000) * 0x14 + 0xc + (xmld == NULL ? 0 : 0x10 + xmls) + 15) / 16 * 16);
                //printf("%s -i %s -a %s %s -o %s\n", allocate, path, arch, ssize, temp);
                execlp(allocate, allocate, "-i", path, "-a", arch, ssize, "-o", temp, NULL);
                _assert(false);
            }

            int status;
            _syscall(waitpid(pid, &status, 0));
            _assert(WIFEXITED(status));
            _assert(WEXITSTATUS(status) == 0);
        }

        Framework framework(temp == NULL ? path : temp);
        struct linkedit_data_command *signature(NULL);

        if (flag_p)
            printf("path%zu='%s'\n", filei, file->c_str());

        if (woffset != _not(uintptr_t)) {
            Pointer<uint32_t> wvalue(framework.GetPointer<uint32_t>(woffset));
            if (wvalue == NULL)
                printf("(null) %p\n", woffset);
            else
                printf("0x%.08x\n", *wvalue);
        }

        if (noffset != _not(uintptr_t))
            printf("%s\n", &*framework.GetPointer<char>(noffset));

        _foreach (load_command, framework.GetLoadCommands()) {
            uint32_t cmd(framework.Swap((*load_command)->cmd));

            if (flag_R && cmd == LC_REEXPORT_DYLIB)
                (*load_command)->cmd = framework.Swap(LC_LOAD_DYLIB);
            else if (cmd == LC_CODE_SIGNATURE)
                signature = reinterpret_cast<struct linkedit_data_command *>(*load_command);
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

        if (flag_e) {
            _assert(signature != NULL);

            uint32_t data = framework.Swap(signature->dataoff);
            uint32_t size = framework.Swap(signature->datasize);

            uint8_t *top = reinterpret_cast<uint8_t *>(framework.GetBase());
            uint8_t *blob = top + data;
            struct SuperBlob *super = reinterpret_cast<struct SuperBlob *>(blob);

            for (size_t index(0); index != Swap(super->count); ++index)
                if (Swap(super->index[index].type) == CSSLOT_ENTITLEMENTS) {
                    uint32_t begin = Swap(super->index[index].offset);
                    struct Blob *entitlements = reinterpret_cast<struct Blob *>(blob + begin);
                    fwrite(entitlements + 1, 1, Swap(entitlements->length) - sizeof(struct Blob), stdout);
                }
        }

        if (flag_s) {
            _assert(signature != NULL);

            uint32_t data = framework.Swap(signature->dataoff);
            uint32_t size = framework.Swap(signature->datasize);

            uint8_t *top = reinterpret_cast<uint8_t *>(framework.GetBase());
            uint8_t *blob = top + data;
            struct SuperBlob *super = reinterpret_cast<struct SuperBlob *>(blob);

            for (size_t index(0); index != Swap(super->count); ++index)
                if (Swap(super->index[index].type) == CSSLOT_CODEDIRECTORY) {
                    uint32_t begin = Swap(super->index[index].offset);
                    struct CodeDirectory *directory = reinterpret_cast<struct CodeDirectory *>(blob + begin);

                    uint8_t (*hashes)[20] = reinterpret_cast<uint8_t (*)[20]>(blob + begin + Swap(directory->hashOffset));
                    uint32_t pages = Swap(directory->nCodeSlots);

                    if (pages != 1)
                        for (size_t i = 0; i != pages - 1; ++i)
                            sha1(hashes[i], top + 0x1000 * i, 0x1000);
                    if (pages != 0)
                        sha1(hashes[pages - 1], top + 0x1000 * (pages - 1), ((data - 1) % 0x1000) + 1);
                }
        }

        if (flag_S) {
            _assert(signature != NULL);

            uint32_t data = framework.Swap(signature->dataoff);
            uint32_t size = framework.Swap(signature->datasize);

            uint8_t *top = reinterpret_cast<uint8_t *>(framework.GetBase());
            uint8_t *blob = top + data;
            struct SuperBlob *super = reinterpret_cast<struct SuperBlob *>(blob);
            super->blob.magic = Swap(CSMAGIC_EMBEDDED_SIGNATURE);

            uint32_t count = xmld == NULL ? 2 : 3;
            uint32_t offset = sizeof(struct SuperBlob) + count * sizeof(struct BlobIndex);

            super->index[0].type = Swap(CSSLOT_CODEDIRECTORY);
            super->index[0].offset = Swap(offset);

            uint32_t begin = offset;
            struct CodeDirectory *directory = reinterpret_cast<struct CodeDirectory *>(blob + begin);
            offset += sizeof(struct CodeDirectory);

            directory->blob.magic = Swap(CSMAGIC_CODEDIRECTORY);
            directory->version = Swap(uint32_t(0x00020001));
            directory->flags = Swap(uint32_t(0));
            directory->codeLimit = Swap(data);
            directory->hashSize = 0x14;
            directory->hashType = 0x01;
            directory->spare1 = 0x00;
            directory->pageSize = 0x0c;
            directory->spare2 = Swap(uint32_t(0));

            directory->identOffset = Swap(offset - begin);
            strcpy(reinterpret_cast<char *>(blob + offset), base);
            offset += strlen(base) + 1;

            uint32_t special = xmld == NULL ? CSSLOT_REQUIREMENTS : CSSLOT_ENTITLEMENTS;
            directory->nSpecialSlots = Swap(special);

            uint8_t (*hashes)[20] = reinterpret_cast<uint8_t (*)[20]>(blob + offset);
            memset(hashes, 0, sizeof(*hashes) * special);

            offset += sizeof(*hashes) * special;
            hashes += special;

            uint32_t pages = (data + 0x1000 - 1) / 0x1000;
            directory->nCodeSlots = Swap(pages);

            if (pages != 1)
                for (size_t i = 0; i != pages - 1; ++i)
                    sha1(hashes[i], top + 0x1000 * i, 0x1000);
            if (pages != 0)
                sha1(hashes[pages - 1], top + 0x1000 * (pages - 1), ((data - 1) % 0x1000) + 1);

            directory->hashOffset = Swap(offset - begin);
            offset += sizeof(*hashes) * pages;
            directory->blob.length = Swap(offset - begin);

            super->index[1].type = Swap(CSSLOT_REQUIREMENTS);
            super->index[1].offset = Swap(offset);

            memcpy(blob + offset, "\xfa\xde\x0c\x01\x00\x00\x00\x0c\x00\x00\x00\x00", 0xc);
            offset += 0xc;

            if (xmld != NULL) {
                super->index[2].type = Swap(CSSLOT_ENTITLEMENTS);
                super->index[2].offset = Swap(offset);

                uint32_t begin = offset;
                struct Blob *entitlements = reinterpret_cast<struct Blob *>(blob + begin);
                offset += sizeof(struct Blob);

                memcpy(blob + offset, xmld, xmls);
                offset += xmls;

                entitlements->magic = Swap(CSMAGIC_ENTITLEMENTS);
                entitlements->length = Swap(offset - begin);
            }

            for (size_t index(0); index != count; ++index) {
                uint32_t type = Swap(super->index[index].type);
                if (type != 0 && type <= special) {
                    uint32_t offset = Swap(super->index[index].offset);
                    struct Blob *local = (struct Blob *) (blob + offset);
                    sha1((uint8_t *) (hashes - type), (uint8_t *) local, Swap(local->length));
                }
            }

            super->count = Swap(count);
            super->blob.length = Swap(offset);

            if (offset > size) {
                fprintf(stderr, "offset (%u) > size (%u)\n", offset, size);
                _assert(false);
            } //else fprintf(stderr, "offset (%zu) <= size (%zu)\n", offset, size);

            memset(blob + offset, 0, size - offset);
        }

        if (flag_S) {
            uint8_t *top = reinterpret_cast<uint8_t *>(framework.GetBase());
            size_t size = framework.GetSize();

            char *copy;
            asprintf(&copy, "%s.%s.cp", dir, base);
            FILE *file = fopen(copy, "w+");
            size_t writ = fwrite(top, 1, size, file);
            _assert(writ == size);
            fclose(file);

            _syscall(unlink(temp));
            free(temp);
            temp = copy;
        }

        if (temp) {
            struct stat info;
            _syscall(stat(path, &info));
            _syscall(chown(temp, info.st_uid, info.st_gid));
            _syscall(chmod(temp, info.st_mode));
            _syscall(unlink(path));
            _syscall(rename(temp, path));
            free(temp);
        }

        free(dir);
        ++filei;
    } catch (const char *) {
        ++filee;
        ++filei;
    }

    return filee;
}

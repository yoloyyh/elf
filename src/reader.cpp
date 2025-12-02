#include <elf/reader.h>
#include <elf/error.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <filesystem>
#include <algorithm>

elf::Reader::Reader(std::shared_ptr<void> buffer) : mBuffer(std::move(buffer)) {

}

std::unique_ptr<elf::IHeader> elf::Reader::header() const {
    auto ident = (unsigned char *) mBuffer.get();

    if (ident[EI_CLASS] == ELFCLASS64) {
        if (ident[EI_DATA] == ELFDATA2LSB)
            return std::make_unique<Header<Elf64_Ehdr, endian::Little>>((const Elf64_Ehdr *) mBuffer.get());
        else
            return std::make_unique<Header<Elf64_Ehdr, endian::Big>>((const Elf64_Ehdr *) mBuffer.get());
    } else {
        if (ident[EI_DATA] == ELFDATA2LSB)
            return std::make_unique<Header<Elf32_Ehdr, endian::Little>>((const Elf32_Ehdr *) mBuffer.get());
        else
            return std::make_unique<Header<Elf32_Ehdr, endian::Big>>((const Elf32_Ehdr *) mBuffer.get());
    }
}

std::vector<std::shared_ptr<elf::ISegment>> elf::Reader::segments() const {
    // 如果缓存为空，则计算并缓存结果
    if (!mSegmentsCache.has_value()) {
        auto header = this->header();
        std::vector<std::shared_ptr<elf::ISegment>> segments;

        for (Elf64_Half i = 0; i < header->segmentNum(); i++) {
            if (header->ident()[EI_CLASS] == ELFCLASS64) {
                auto segment = (const Elf64_Phdr *) (
                        (const std::byte *) mBuffer.get() +
                        header->segmentOffset() +
                        i * header->segmentEntrySize()
                );

                if (header->ident()[EI_DATA] == ELFDATA2LSB)
                    segments.push_back(std::make_shared<Segment<Elf64_Phdr, endian::Little>>(segment, mBuffer));
                else
                    segments.push_back(std::make_shared<Segment<Elf64_Phdr, endian::Big>>(segment, mBuffer));
            } else {
                auto segment = (const Elf32_Phdr *) (
                        (const std::byte *) mBuffer.get() +
                        header->segmentOffset() +
                        i * header->segmentEntrySize()
                );

                if (header->ident()[EI_DATA] == ELFDATA2LSB)
                    segments.push_back(std::make_shared<Segment<Elf32_Phdr, endian::Little>>(segment, mBuffer));
                else
                    segments.push_back(std::make_shared<Segment<Elf32_Phdr, endian::Big>>(segment, mBuffer));
            }
        }

        mSegmentsCache = segments;
    }

    return *mSegmentsCache;
}

std::vector<std::shared_ptr<elf::ISection>> elf::Reader::sections() const {
    auto header = this->header();
    std::vector<std::shared_ptr<elf::ISection>> sections;

    for (Elf64_Half i = 0; i < header->sectionNum(); i++) {
        if (header->ident()[EI_CLASS] == ELFCLASS64) {
            auto section = (const Elf64_Shdr *) (
                    (std::byte *) mBuffer.get() +
                    header->sectionOffset() +
                    i * header->sectionEntrySize()
            );

            if (header->ident()[EI_DATA] == ELFDATA2LSB)
                sections.push_back(std::make_shared<Section<Elf64_Shdr, endian::Little>>(section, mBuffer));
            else
                sections.push_back(std::make_shared<Section<Elf64_Shdr, endian::Big>>(section, mBuffer));
        } else {
            auto section = (const Elf32_Shdr *) (
                    (std::byte *) mBuffer.get() +
                    header->sectionOffset() +
                    i * header->sectionEntrySize()
            );

            if (header->ident()[EI_DATA] == ELFDATA2LSB)
                sections.push_back(std::make_shared<Section<Elf32_Shdr, endian::Little>>(section, mBuffer));
            else
                sections.push_back(std::make_shared<Section<Elf32_Shdr, endian::Big>>(section, mBuffer));
        }
    }

    for (const auto &section: sections)
        section->name((char *) sections[header->sectionStrIndex()]->data() + section->nameIndex());

    return sections;
}

const std::byte *elf::Reader::virtualMemory(Elf64_Addr address) const {
    // 使用缓存的segments，避免重复计算
    const auto& segments = this->segments();

    auto it = std::find_if(
            segments.begin(),
            segments.end(),
            [=](const auto &segment) {
                if (segment->type() != PT_LOAD)
                    return false;

                return address >= segment->virtualAddress() &&
                       address <= segment->virtualAddress() + segment->fileSize() - 1;
            }
    );

    if (it == segments.end())
        return nullptr;

    return it->operator*().data() + address - it->operator*().virtualAddress();
}

std::optional<std::vector<std::byte>> elf::Reader::readVirtualMemory(Elf64_Addr address, Elf64_Xword length) const {
    if (length == 0) return std::vector<std::byte>{};

    // 使用缓存的segments，避免重复计算
    const auto& segments = this->segments();
    std::vector<std::byte> out;
    out.reserve(length);

    uint64_t cur = address;
    size_t remaining = (size_t) length;

    while (remaining > 0) {
        auto it = std::find_if(segments.begin(), segments.end(), [&](const auto &segment) {
            if (segment->type() != PT_LOAD) return false;
            uint64_t va = segment->virtualAddress();
            uint64_t memsz = segment->memorySize();
            return cur >= va && cur < va + memsz;
        });

        if (it == segments.end()) {
            // unmapped virtual address
            return std::nullopt;
        }

        auto seg = *it;
        uint64_t seg_va = seg->virtualAddress();
        uint64_t seg_filesz = seg->fileSize();
        uint64_t seg_memsz = seg->memorySize();

        // how many bytes remain in this segment (up to memsz)
        uint64_t seg_left = (seg_va + seg_memsz) - cur;
        size_t chunk = (size_t) std::min<uint64_t>(seg_left, remaining);

        // offset within file-backed data
        uint64_t offset_in_seg = cur - seg_va;

        // if offset falls within file-backed area, copy available file bytes
        if (offset_in_seg < seg_filesz) {
            uint64_t file_avail = seg_filesz - offset_in_seg;
            size_t copy_bytes = (size_t) std::min<uint64_t>(file_avail, chunk);
            const std::byte *src = seg->data() + offset_in_seg;
            out.insert(out.end(), src, src + copy_bytes);

            // if chunk > copy_bytes, remaining part must be zero (BSS)
            if (copy_bytes < chunk) {
                size_t zeros = chunk - copy_bytes;
                out.insert(out.end(), zeros, std::byte{0});
            }
        } else {
            // entirely in bss (no file data), fill zeros
            out.insert(out.end(), chunk, std::byte{0});
        }

        cur += chunk;
        remaining -= chunk;
    }

    return out;
}

tl::expected<elf::Reader, std::error_code> elf::openFile(const std::filesystem::path &path) {
    std::error_code ec;
    size_t length = std::filesystem::file_size(path, ec);

    if (ec != std::errc())
        return tl::unexpected(ec);

    if (length < EI_NIDENT)
        return tl::unexpected(Error::INVALID_ELF_HEADER);

    int fd = open(path.string().c_str(), O_RDONLY);

    if (fd < 0)
        return tl::unexpected(std::error_code(errno, std::system_category()));

    void *buffer = mmap(
            nullptr,
            length,
            PROT_READ,
            MAP_PRIVATE,
            fd,
            0
    );

    if (buffer == MAP_FAILED) {
        close(fd);
        return tl::unexpected(std::error_code(errno, std::system_category()));
    }

    close(fd);

    auto ident = (unsigned char *) buffer;

    if (ident[EI_MAG0] != ELFMAG0 ||
        ident[EI_MAG1] != ELFMAG1 ||
        ident[EI_MAG2] != ELFMAG2 ||
        ident[EI_MAG3] != ELFMAG3) {
        munmap(buffer, length);
        return tl::unexpected(Error::INVALID_ELF_MAGIC);
    }

    if (ident[EI_CLASS] != ELFCLASS64 && ident[EI_CLASS] != ELFCLASS32) {
        munmap(buffer, length);
        return tl::unexpected(Error::INVALID_ELF_CLASS);
    }

    if (ident[EI_DATA] != ELFDATA2LSB && ident[EI_DATA] != ELFDATA2MSB) {
        munmap(buffer, length);
        return tl::unexpected(Error::INVALID_ELF_ENDIAN);
    }

    return Reader(std::shared_ptr<void>(buffer, [=](void *ptr) {
        munmap(ptr, length);
    }));
}

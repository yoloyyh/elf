#include <elf/symbol.h>

template<typename T, elf::endian::Type Endian>
elf::Symbol<T, Endian>::Symbol(const T *symbol) : mSymbol(symbol) {

}

template<typename T, elf::endian::Type Endian>
std::string elf::Symbol<T, Endian>::name() {
    return mName;
}

template<typename T, elf::endian::Type Endian>
void elf::Symbol<T, Endian>::name(std::string_view name) {
    mName = name;
}

template<typename T, elf::endian::Type Endian>
Elf64_Word elf::Symbol<T, Endian>::nameIndex() {
    return endian::convert<Endian>(mSymbol->st_name);
}

template<typename T, elf::endian::Type Endian>
unsigned char elf::Symbol<T, Endian>::info() {
    return mSymbol->st_info;
}

template<typename T, elf::endian::Type Endian>
unsigned char elf::Symbol<T, Endian>::other() {
    return mSymbol->st_other;
}

template<typename T, elf::endian::Type Endian>
Elf64_Section elf::Symbol<T, Endian>::sectionIndex() {
    return endian::convert<Endian>(mSymbol->st_shndx);
}

template<typename T, elf::endian::Type Endian>
Elf64_Addr elf::Symbol<T, Endian>::value() {
    return endian::convert<Endian>(mSymbol->st_value);
}

template<typename T, elf::endian::Type Endian>
Elf64_Xword elf::Symbol<T, Endian>::size() {
    return endian::convert<Endian>(mSymbol->st_size);
}

elf::SymbolIterator::SymbolIterator(
        const std::byte *symbol,
        size_t size,
        endian::Type endian,
        std::shared_ptr<ISection> section
) : mSymbol(symbol), mSize(size), mEndian(endian), mSection(std::move(section)) {

}

std::unique_ptr<elf::ISymbol> elf::SymbolIterator::operator*() {
    std::unique_ptr<elf::ISymbol> symbol;

    if (mSize == sizeof(Elf64_Sym)) {
        if (mEndian == endian::Little)
            symbol = std::make_unique<Symbol<Elf64_Sym, endian::Little>>((const Elf64_Sym *) mSymbol);
        else
            symbol = std::make_unique<Symbol<Elf64_Sym, endian::Big>>((const Elf64_Sym *) mSymbol);
    } else {
        if (mEndian == endian::Little)
            symbol = std::make_unique<Symbol<Elf32_Sym, endian::Little>>((const Elf32_Sym *) mSymbol);
        else
            symbol = std::make_unique<Symbol<Elf32_Sym, endian::Big>>((const Elf32_Sym *) mSymbol);
    }

    if (!symbol->nameIndex())
        return symbol;

    symbol->name((char *) mSection->data() + symbol->nameIndex());

    return symbol;
}

elf::SymbolIterator &elf::SymbolIterator::operator--() {
    mSymbol -= mSize;
    return *this;
}

elf::SymbolIterator &elf::SymbolIterator::operator++() {
    mSymbol += mSize;
    return *this;
}

elf::SymbolIterator &elf::SymbolIterator::operator+=(std::ptrdiff_t offset) {
    mSymbol += offset * mSize;
    return *this;
}

elf::SymbolIterator elf::SymbolIterator::operator-(std::ptrdiff_t offset) {
    return {mSymbol - offset * mSize, mSize, mEndian, mSection};
}

elf::SymbolIterator elf::SymbolIterator::operator+(std::ptrdiff_t offset) {
    return {mSymbol + offset * mSize, mSize, mEndian, mSection};
}

bool elf::SymbolIterator::operator==(const elf::SymbolIterator &rhs) {
    return mSymbol == rhs.mSymbol;
}

bool elf::SymbolIterator::operator!=(const elf::SymbolIterator &rhs) {
    return !operator==(rhs);
}

std::ptrdiff_t elf::SymbolIterator::operator-(const elf::SymbolIterator &rhs) {
    return (mSymbol - rhs.mSymbol) / (std::ptrdiff_t) mSize;
}

elf::SymbolTable::SymbolTable(elf::Reader reader, std::shared_ptr<ISection> section)
        : mReader(std::move(reader)), mSection(std::move(section)) {

}

size_t elf::SymbolTable::size() {
    if (mSection->entrySize() == 0) {
        return 0;
    }
    return mSection->size() / mSection->entrySize();
}

std::unique_ptr<elf::ISymbol> elf::SymbolTable::operator[](size_t index) {
    return *(begin() + (std::ptrdiff_t) index);
}

elf::SymbolIterator elf::SymbolTable::begin() {
    return {
            mSection->data(),
            mSection->entrySize(),
            mReader.header()->ident()[EI_DATA] == ELFDATA2LSB ? endian::Little : endian::Big,
            mReader.sections()[mSection->link()]
    };
}

elf::SymbolIterator elf::SymbolTable::end() {
    return begin() + (std::ptrdiff_t) size();
}

template
class elf::Symbol<Elf32_Sym, elf::endian::Little>;

template
class elf::Symbol<Elf32_Sym, elf::endian::Big>;

template
class elf::Symbol<Elf64_Sym, elf::endian::Little>;

template
class elf::Symbol<Elf64_Sym, elf::endian::Big>;
import codecs
import sys

from binaryninja.log import log_warn

if sys.version_info[0] == 3:
    decode_as = "ascii"
else:
    decode_as = None

PE_32BIT = 0x10b
PE_64BIT = 0x20b

# Silence code testing tools
if None:
    bv = None


def get_directory_addr(bv, directory_offset):
    raw = bv.parent_view if bv.parent_view else bv
    pe_offset = get_pe_header_addr(bv)
    # Quick and dirty size-agnostic cross-version bytes-to-int conversion
    field_offset = raw.read_int(pe_offset + directory_offset, 4)
    if not field_offset:
        return 0

    dir_addr = bv.start + field_offset

    return dir_addr


def get_pe_magic(bv):
    raw = bv.parent_view if bv.parent_view else bv
    pe_offset = get_pe_header_addr(bv)

    return read_int(raw, pe_offset + 0x18, 2)


def get_eat_addr(bv):
    magic = get_pe_magic(bv)

    if magic == PE_32BIT:
        return get_directory_addr(bv, 0x78)

    if magic == PE_64BIT:
        return get_directory_addr(bv, 0x88)

    raise Exception


def get_iat_addr(bv):
    magic = get_pe_magic(bv)

    if magic == PE_32BIT:
        return get_directory_addr(bv, 0x80)

    if magic == PE_64BIT:
        return get_directory_addr(bv, 0x90)

    raise Exception


def read_int(bv, addr, len_=None):
    if not len_:
        len_ = bv.address_size

    val = bv.read(addr, len_)

    if not val:
        return 0

    # Quick and dirty size-agnostic cross-version bytes-to-int conversion
    return int(codecs.encode(val[::-1], "hex"), 16)


def get_pe_header_addr(bv):
    raw = bv.parent_view if bv.parent_view else bv if bv.parent_view else bv
    base_addr = raw.perform_get_start()
    pe_offset = read_int(raw, base_addr + 0x3c, 4)
    pe_addr = base_addr + pe_offset

    return pe_addr


class Export(object):
    def __init__(self, addr, symbol, ord_, hint, name_index=0):
        self.addr = addr
        self.ord = ord_
        self.symbol = symbol
        self.name_index = name_index

    @property
    def name(self):
        # symbol.name is the mangled name, full_name is demangled
        name = self.symbol.full_name

        if not name:
            name = "unnamed_export"

        if self.name_index > 1:
            name += "#%d" % self.name_index

        return name

    def __repr__(self):
        return "Export(Ord %x, 0x%08x: `%s`)" % (self.ord, self.addr,
                                                 self.name)


def get_eat_name(bv):
    eat = get_eat_addr(bv)
    if not eat:
        return ""

    dll_name_ptr = bv.start + read_int(bv, eat + 0xc, 4)
    dll_name = read_cstring(bv, dll_name_ptr)
    if decode_as:
        dll_name = dll_name.decode(decode_as)
    return dll_name


def get_exports(bv):
    eat = get_eat_addr(bv)
    if not eat:
        return []

    ord_base = read_int(bv, eat + 0x10, 4)
    eat_addr_items = read_int(bv, eat + 0x14, 4)
    eat_name_ptrs = read_int(bv, eat + 0x18, 4)
    eat_addr_rva = read_int(bv, eat + 0x1c, 4)
    name_addr_rva = read_int(bv, eat + 0x20)
    ord_addr_rva = read_int(bv, eat + 0x24, 4)

    # Keep track of how many ordinals refer to a given symbol
    name_counter = {}

    exports = []
    for hint in range(eat_name_ptrs):
        ord_ = read_int(bv, bv.start + ord_addr_rva + hint * 2, 2) # by hint
        addr = bv.start + read_int(bv, bv.start + eat_addr_rva + ord_ * 4, 4)
        name_ptr = bv.start + read_int(bv, bv.start + name_addr_rva + hint * bv.address_size)
        name = read_cstring(bv, name_ptr) # mangled name
        if decode_as:
            name = name.decode(decode_as)
        symbol = bv.get_symbol_at(addr)
        for symbol in bv.get_symbols(start=addr):
            if symbol.name == name:
                break
        else:
            log_warn("Unable to find symbol for export %r with hint %d" % (name, hint))
            continue

        # Dupe export counting
        if name not in name_counter:
            name_counter[name] = 0
        name_counter[name] += 1

        exports.append(Export(addr, symbol, ord_ + ord_base, hint,
                              name_index=name_counter[name]))

    return exports


def read_cstring(bv, addr):
    end = bv.find_next_data(addr, b"\x00")
    length = end - addr
    return bv.read(addr, length)


class Library(object):
    def __init__(self, name, lookup_table, import_table):
        self.name = name
        self.lookup_table = lookup_table
        self.import_table = import_table
        self.imports = []

    def __repr__(self):
        return "Library(%r)" % self.name

    def read_imports(self, bv):
        n = 0
        flag_mask = (1 << (bv.address_size * 8 - 1)) - 1
        while True:
            lookup = read_int(bv, self.lookup_table + n * bv.address_size)
            if not lookup:
                break
            datavar_addr = self.import_table + n * bv.address_size
            n += 1

            # We won't find *any* info here if this is an ordinal import.
            if lookup & ~flag_mask:
                # Strip the ordinal flag
                lookup &= flag_mask
                self.imports.append(Import(lookup, None, datavar_addr))
                continue

            lookup += bv.start

            ordinal = read_int(bv, lookup, 2)
            name = read_cstring(bv, lookup + 2)

            if decode_as:
                name = name.decode(decode_as)

            import_ = Import(ordinal, name, datavar_addr)

            self.imports.append(import_)


class Import(object):
    def __init__(self, ordinal, name, datavar_addr):
        self.ordinal = ordinal
        self.name = name
        self.datavar_addr = datavar_addr

    def __repr__(self):
        return "Import(%r, %r, 0x%08x)" % (self.ordinal, self.name,
                                           self.datavar_addr)


def get_imports(bv):
    iat = get_iat_addr(bv)
    if not iat:
        return []

    imports = []

    n = 0
    while True:
        lookup_table_rva = read_int(bv, iat + n * (4 * 5), 4)
        if not lookup_table_rva:
            break
        lookup_table = bv.start + lookup_table_rva
        import_table = bv.start + read_int(bv, iat + n * (4 * 5) + 0x10, 4)

        name_addr = bv.start + read_int(bv, iat + n * (4 * 5) + 0xc, 4)
        name = read_cstring(bv, name_addr)

        if decode_as:
            name = name.decode(decode_as)

        lib = Library(name, lookup_table, import_table)
        lib.read_imports(bv)

        imports.append(lib)
        n += 1

    return imports

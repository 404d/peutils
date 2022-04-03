import codecs
import sys

import binaryninja.interaction
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.function import DisassemblyTextLine, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType

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
    raw = bv.parent_view
    pe_offset = get_pe_header_addr(bv)
    field_offset = raw.read(pe_offset + directory_offset, 4)

    # Quick and dirty size-agnostic cross-version bytes-to-int conversion
    field_offset = int(codecs.encode(field_offset[::-1], "hex"), 16)
    dir_addr = bv.start + field_offset

    return dir_addr


def get_pe_magic(bv):
    raw = bv.parent_view
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
    raw = bv.parent_view
    base_addr = raw.perform_get_start()
    pe_offset = read_int(raw, base_addr + 0x3c, 4)
    pe_addr = base_addr + pe_offset

    return pe_addr


class Export(object):
    def __init__(self, addr, symbol, ord_, name_index=0):
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

    dll_name_ptr = bv.start + read_int(bv, eat + 0xc, 4)
    dll_name = bv.get_strings(dll_name_ptr)[0].value
    return dll_name


def get_exports(bv):
    eat = get_eat_addr(bv)

    eat_items = read_int(bv, eat + 0x14, 4)
    eat_addr = read_int(bv, eat + 0x1c, 4)
    ord_addr = read_int(bv, eat + 0x24, 4)
    # name_addr = read_int(raw, eat + 0x20)

    # Keep track of how many ordinals refer to a given symbol
    name_counter = {}

    exports = []
    for n in range(eat_items):
        addr = bv.start + read_int(bv, bv.start + eat_addr + n * 4, 4)
        ord_ = read_int(bv, bv.start + ord_addr + n * 2, 2)
        # name_ptr = bv.start + read_int(raw, name_addr + n * bv.address_size)
        symbol = bv.get_symbol_at(addr)

        # Dupe export counting
        if symbol.name.lower() not in name_counter:
            name_counter[symbol.name.lower()] = 0
        name_counter[symbol.name.lower()] += 1

        exports.append(Export(addr, symbol, ord_,
                              name_index=name_counter[symbol.name.lower()]))

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
        while read_int(bv, self.lookup_table + n * bv.address_size):
            lookup = read_int(bv, self.lookup_table + n * bv.address_size)
            datavar_addr = self.import_table + n * bv.address_size
            n += 1

            # We won't find *any* info here if this is an ordinal import.
            if lookup >> (bv.address_size * 8 - 1):
                # Strip the ordinal flag
                lookup ^= 1 << (bv.address_size * 8 - 1)
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


def get_imports(bv):
    iat = get_iat_addr(bv)

    imports = []

    n = 0
    while read_int(bv, iat + n * (4 * 5), 4):
        lookup_table = bv.start + read_int(bv, iat + n * (4 * 5), 4)
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

from binaryninja.log import log_warn, log_info, log_error
from binaryninja.types import Symbol
from binaryninja.enums import SymbolType
from binaryninja.demangle import demangle_ms

import peutils

from peutils import pe_parsing


def resolve_imports(bv):
    libs = pe_parsing.get_imports(bv)

    for lib in libs:
        if lib.name.lower() in peutils.files:
            resolve_imports_for_library(bv, lib)


def resolve_imports_for_library(bv, lib):
    source_bv = peutils.files[lib.name.lower()]
    exports = pe_parsing.get_exports(source_bv)
    
    export_by_ord = {export.ord: export for export in exports}

    for import_ in lib.imports:
        # Find the name
        name = None
        if import_.ordinal in export_by_ord:
            export = export_by_ord[import_.ordinal]
            log_info(repr(export))
            name = export.name
            export_symbol = export.symbol

        if not name:
            log_warn("Unable to find name for %r" % import_)
            continue

        # Redefine the IAT thunk symbol
        original_symbol = bv.get_symbol_at(import_.datavar_addr)

        # Delete any existing auto symbols
        if original_symbol:
            log_info("Renaming %s to %s:%s" % (original_symbol.name, lib.name,
                                               name))
            bv.undefine_auto_symbol(original_symbol)
        else:
            log_info("Creating IAT symbol %s:%s @ %08x" %
                     (lib.name.split(".")[0], name, import_.datavar_addr))

        # Create the new symbol
        bv.define_auto_symbol(Symbol(
            SymbolType.ImportAddressSymbol, import_.datavar_addr, name + "@IAT",
            namespace=lib.name.split(".")[0],
        ))

        # Transplant type info
        export_func = source_bv.get_function_at(export_symbol.address)
        if not export_func:
            log_warn(
                "Unable to resolve function for export %r in library %r" %
                (export_symbol, lib)
            )
            continue

        try:
            (type_, name) = demangle_ms(bv.arch, export_symbol.name)
        except:
            log_error("Invalid name, skipping")
            continue

        if type_ is None:
            type_tokens = [token.text for token in export_func.type_tokens]
            if export_symbol.name not in type_tokens:
                log_error("Unknown error")
                continue
            i = type_tokens.index(export_symbol.name)
            type_tokens[i] = "(*const func_name)"

            type_string = "".join(type_tokens)
            log_info("Setting type for %s to %r" % (name, type_string))

            try:
                (type_, name) = bv.parse_type_string(type_string)
            except:
                log_error("Invalid type, skipping")

        bv.define_data_var(import_.datavar_addr, type_)

        # FIXME: Apply params to ImportedFunctionSymbols -- check xref on
        # datavar and filter by associated symbols
        # This doesn't actually seem to help and apparently I didn't have to do
        # this before? Maybe I just didn't handle jump
        """
        for ref in bv.get_code_refs(import_.datavar_addr):
            if ref.function.symbol.type is not SymbolType.ImportedFunctionSymbol:
                continue

            type_tokens = [token.text for token in export_func.type_tokens]
            type_string = "".join(type_tokens)
            (type_, name) = bv.parse_type_string(type_string)
            print(type_)
            bv.define_data_var(ref.function.start, type_)
        """

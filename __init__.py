"""omfg yes finally i bothered fixing this

Notes:
    - The integer size for both tables and headers are the same between 32 and
      64-bit, with the exception of certain pointers in the import directory
      itself
    - Something's weird with the way the raw binaryview works on 64-bit, so
      prefer the PE view whenever
    - Apparently a binary can export the same function under the same name but
      different ordinals. We'll fix this by naming exports as follows:
        - export_name
        - export_name#2
        - export_name#3
        - etc...

Todo:
    - Proper handling of users loading EAT-less binaries using the load command
        - Should I just ignore it? Add it but never look up the BV?
    - Use StructuredDataView to get some of the stuff?
        https://api.binary.ninja/binaryninja.binaryview.StructuredDataView.html
    - Symbol syncing
    - Automatically register new views
    - Use DB symbol names for exports and imports, especially when using symbol
      syncing
    - Looks like imports with jump stubs doesn't get their types set correctly?

"""
from binaryninja.plugin import PluginCommand

from . import pe_parsing, reports, sync


files = {}


def bv_is_pe(bv):
    return bv.view_type == "PE"


def all_bvs(func):

    def wrapper(bv):
        bvs = files.values()
        # bvs = set([bv] + bvs)
        func(bvs)

    return wrapper


def register_file(bv):
    # name = os.path.basename(bv.file.filename).split(".")[0]
    name = pe_parsing.get_eat_name(bv)

    files[name.lower()] = bv


PluginCommand.register(
    "PE\\Load binary",
    "Load the current binary into the PE binary registry",
    register_file, is_valid=bv_is_pe
)
PluginCommand.register(
    "PE\\Resolve imports",
    "Resolve import names and load types",
    sync.resolve_imports, is_valid=bv_is_pe
)


PluginCommand.register(
    "PE\\Debug\\PE tables",
    "Show the IAT and EAT as seen by PE Utils",
    reports.generate_table_graph, is_valid=bv_is_pe
)
PluginCommand.register(
    "PE\\Debug\\Binary relationship graph",
    "Show a relationship graph for the currently loaded BVs",
    all_bvs(reports.generate_relation_graph), is_valid=bv_is_pe
)

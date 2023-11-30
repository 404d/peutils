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
import os
import traceback

import binaryninja
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import (
    TextLineField, DirectoryNameField,
    get_form_input, show_message_box
)
from binaryninja import log_info

from . import pe_parsing, reports, sync, comhelper
from .data import files


def bv_is_pe(bv):
    return bv.view_type == "PE"


def all_bvs(func):

    def wrapper(bv):
        bvs = files.values()
        # bvs = set([bv] + bvs)
        func(bvs)

    return wrapper


def select_bvs(func):

    def wrapper(bv):
        ext_field = TextLineField("Extensions", default="exe,dll")
        dir_field = DirectoryNameField("Directory")
        get_form_input([ext_field, dir_field], "Binary Dependency Graph")
        exts = ['.' + ext for ext in ext_field.result.split(",") if ext]
        if not exts:
            show_message_box("Error", "No extensions specified")
            return
        directory = dir_field.result
        if not os.path.exists(directory):
            show_message_box("Error", "Directory does not exist")
            return

        bvs = []
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if not file.endswith(tuple(exts)):
                        continue
                    path = os.path.join(root, file)
                    bv = binaryninja.open_view(path, update_analysis=False)
                    bvs.append(bv)
                    if bv.view_type == "PE":
                        bvs.append(bv)
            func(bvs)
        except Exception as e:
            show_message_box("Error", traceback.format_exc())
            return
        finally:
            for bv in bvs:
                bv.file.close()

    return wrapper


def register_file(bv):
    # name = os.path.basename(bv.file.filename).split(".")[0]
    name = pe_parsing.get_eat_name(bv)

    files[name.lower()] = bv
    log_info("Registered PE binary view %r" % name.lower())


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
PluginCommand.register(
    "PE\\Debug\\Binary relationship graph (selected)",
    "Show a relationship graph for the currently loaded BVs",
    select_bvs(reports.generate_relation_graph), is_valid=lambda _: True
)

PluginCommand.register_for_address(
    "PE\\COM\\Resolve Interface ID",
    "Resolve interface id of COM object",
    comhelper.resolve_iid, is_valid=lambda bv, _: bv_is_pe(bv)
)
PluginCommand.register_for_address(
    "PE\\COM\\Resolve Class ID",
    "Resolve class id of COM object",
    comhelper.resolve_clsid, is_valid=lambda bv, _: bv_is_pe(bv)
)

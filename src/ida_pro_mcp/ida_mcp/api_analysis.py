from typing import Annotated, Optional
import time
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_funcs
import idaapi
import idautils
import idc
import ida_typeinf
import ida_nalt
import ida_bytes
import ida_ida
import ida_entry
import ida_search
import ida_idaapi
import ida_xref
from .rpc import tool
from .sync import idaread, is_window_active
from .utils import (
    parse_address,
    normalize_list_input,
    get_function,
    get_prototype,
    get_stack_frame_variables_internal,
    decompile_checked,
    decompile_function_safe,
    get_assembly_lines,
    get_all_xrefs,
    get_all_comments,
    get_callees,
    get_callers,
    get_xrefs_from_internal,
    extract_function_strings,
    extract_function_constants,
    Function,
    Argument,
    DisassemblyFunction,
    Xref,
    FunctionAnalysis,
    BasicBlock,
    PathQuery,
    StructFieldQuery,
    StringFilter,
    InsnPattern,
)

# ============================================================================
# String Cache
# ============================================================================

# Cache for idautils.Strings() to avoid rebuilding on every call
_strings_cache: Optional[list[dict]] = None
_strings_cache_md5: Optional[str] = None


def _get_cached_strings_dict() -> list[dict]:
    """Get cached strings as dicts, rebuilding if IDB changed"""
    global _strings_cache, _strings_cache_md5

    # Get current IDB modification hash
    current_md5 = ida_nalt.retrieve_input_file_md5()

    # Rebuild cache if needed
    if _strings_cache is None or _strings_cache_md5 != current_md5:
        _strings_cache = []
        for s in idautils.Strings():
            try:
                _strings_cache.append(
                    {
                        "addr": hex(s.ea),
                        "length": s.length,
                        "string": str(s),
                        "type": s.strtype,
                    }
                )
            except Exception:
                pass
        _strings_cache_md5 = current_md5

    return _strings_cache


# ============================================================================
# Code Analysis & Decompilation
# ============================================================================


@tool
@idaread
def decompile(
    addrs: Annotated[list[str] | str, "Function addresses to decompile"],
) -> list[dict]:
    """Decompile functions to pseudocode"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            start = parse_address(addr)
            cfunc = decompile_checked(start)
            if is_window_active():
                ida_hexrays.open_pseudocode(start, ida_hexrays.OPF_REUSE)
            sv = cfunc.get_pseudocode()
            code = ""
            for i, sl in enumerate(sv):
                sl: ida_kernwin.simpleline_t
                item = ida_hexrays.ctree_item_t()
                ea = None if i > 0 else cfunc.entry_ea
                if cfunc.get_line_item(sl.line, 0, False, None, item, None):
                    dstr: str | None = item.dstr()
                    if dstr:
                        ds = dstr.split(": ")
                        if len(ds) == 2:
                            try:
                                ea = int(ds[0], 16)
                            except ValueError:
                                pass
                line = ida_lines.tag_remove(sl.line)
                if len(code) > 0:
                    code += "\n"
                if not ea:
                    code += f"/* line: {i} */ {line}"
                else:
                    code += f"/* line: {i}, address: {hex(ea)} */ {line}"

            results.append({"addr": addr, "code": code})
        except Exception as e:
            results.append({"addr": addr, "code": None, "error": str(e)})

    return results


@tool
@idaread
def disasm(
    addrs: Annotated[list[str] | str, "Function addresses to disassemble"],
    max_instructions: Annotated[
        int, "Max instructions per function (default: 5000, max: 50000)"
    ] = 5000,
    offset: Annotated[int, "Skip first N instructions (default: 0)"] = 0,
) -> list[dict]:
    """Disassemble functions to assembly instructions"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if max_instructions <= 0 or max_instructions > 50000:
        max_instructions = 50000

    results = []

    for start_addr in addrs:
        try:
            start = parse_address(start_addr)
            func = idaapi.get_func(start)

            if is_window_active():
                ida_kernwin.jumpto(start)

            # Get segment info
            seg = idaapi.getseg(start)
            if not seg:
                results.append(
                    {
                        "addr": start_addr,
                        "asm": None,
                        "error": "No segment found",
                        "cursor": {"done": True},
                    }
                )
                continue

            segment_name = idaapi.get_segm_name(seg) if seg else "UNKNOWN"

            # Collect instructions
            all_instructions = []

            if func:
                # Function exists: disassemble function items starting from requested address
                func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
                header_addr = start  # Use requested address, not function start

                for ea in idautils.FuncItems(func.start_ea):
                    if ea == idaapi.BADADDR:
                        continue
                    # Skip instructions before the requested start address
                    if ea < start:
                        continue

                    # Use generate_disasm_line to get full line with comments
                    line = idc.generate_disasm_line(ea, 0)
                    instruction = ida_lines.tag_remove(line) if line else ""
                    all_instructions.append((ea, instruction))
            else:
                # No function: disassemble sequentially from start address
                func_name = f"<no function>"
                header_addr = start

                ea = start
                while ea < seg.end_ea and len(all_instructions) < max_instructions + offset:
                    if ea == idaapi.BADADDR:
                        break

                    insn = idaapi.insn_t()
                    if idaapi.decode_insn(insn, ea) == 0:
                        break

                    # Use generate_disasm_line to get full line with comments
                    line = idc.generate_disasm_line(ea, 0)
                    instruction = ida_lines.tag_remove(line) if line else ""
                    all_instructions.append((ea, instruction))

                    ea = idc.next_head(ea, seg.end_ea)

            # Apply pagination
            total_insns = len(all_instructions)
            paginated_insns = all_instructions[offset : offset + max_instructions]
            has_more = offset + max_instructions < total_insns

            # Build disassembly string from paginated instructions
            lines_str = f"{func_name} ({segment_name} @ {hex(header_addr)}):"
            for ea, instruction in paginated_insns:
                lines_str += f"\n{ea:x}  {instruction}"

            rettype = None
            args: Optional[list[Argument]] = None
            stack_frame = None

            if func:
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
                    ftd = ida_typeinf.func_type_data_t()
                    if tif.get_func_details(ftd):
                        rettype = str(ftd.rettype)
                        args = [
                            Argument(name=(a.name or f"arg{i}"), type=str(a.type))
                            for i, a in enumerate(ftd)
                        ]
                stack_frame = get_stack_frame_variables_internal(func.start_ea, False)

            out: DisassemblyFunction = {
                "name": func_name,
                "start_ea": hex(header_addr),
                "lines": lines_str,
            }
            if stack_frame:
                out["stack_frame"] = stack_frame
            if rettype:
                out["return_type"] = rettype
            if args is not None:
                out["arguments"] = args

            results.append(
                {
                    "addr": start_addr,
                    "asm": out,
                    "instruction_count": len(paginated_insns),
                    "total_instructions": total_insns,
                    "cursor": (
                        {"next": offset + max_instructions}
                        if has_more
                        else {"done": True}
                    ),
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": start_addr,
                    "asm": None,
                    "error": str(e),
                    "cursor": {"done": True},
                }
            )

    return results


# ============================================================================
# Cross-Reference Analysis
# ============================================================================


@tool
@idaread
def xrefs_to(
    addrs: Annotated[list[str] | str, "Addresses to find cross-references to"],
) -> list[dict]:
    """Get all cross-references to specified addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(parse_address(addr)):
                xrefs += [
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                ]
            results.append({"addr": addr, "xrefs": xrefs})
        except Exception as e:
            results.append({"addr": addr, "xrefs": None, "error": str(e)})

    return results


@tool
@idaread
def xrefs_to_field(queries: list[StructFieldQuery] | StructFieldQuery) -> list[dict]:
    """Get cross-references to structure fields"""
    if isinstance(queries, dict):
        queries = [queries]

    results = []
    til = ida_typeinf.get_idati()
    if not til:
        return [
            {
                "struct": q.get("struct"),
                "field": q.get("field"),
                "xrefs": [],
                "error": "Failed to retrieve type library",
            }
            for q in queries
        ]

    for query in queries:
        struct_name = query.get("struct", "")
        field_name = query.get("field", "")

        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(
                til, struct_name, ida_typeinf.BTF_STRUCT, True, False
            ):
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)
            if idx == -1:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Field '{field_name}' not found in '{struct_name}'",
                    }
                )
                continue

            tid = tif.get_udm_tid(idx)
            if tid == ida_idaapi.BADADDR:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": "Unable to get tid",
                    }
                )
                continue

            xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(tid):
                xrefs += [
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                ]
            results.append({"struct": struct_name, "field": field_name, "xrefs": xrefs})
        except Exception as e:
            results.append(
                {
                    "struct": struct_name,
                    "field": field_name,
                    "xrefs": [],
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Call Graph Analysis
# ============================================================================


@tool
@idaread
def callees(
    addrs: Annotated[list[str] | str, "Function addresses to get callees for"],
) -> list[dict]:
    """Get all functions called by the specified functions"""
    addrs = normalize_list_input(addrs)
    results = []

    for fn_addr in addrs:
        try:
            func_start = parse_address(fn_addr)
            func = idaapi.get_func(func_start)
            if not func:
                results.append(
                    {"addr": fn_addr, "callees": None, "error": "No function found"}
                )
                continue
            func_end = idc.find_func_end(func_start)
            callees: list[dict[str, str]] = []
            current_ea = func_start
            while current_ea < func_end:
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, current_ea)
                if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                    target = idc.get_operand_value(current_ea, 0)
                    target_type = idc.get_operand_type(current_ea, 0)
                    if target_type in [idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                        func_type = (
                            "internal"
                            if idaapi.get_func(target) is not None
                            else "external"
                        )
                        func_name = idc.get_name(target)
                        if func_name is not None:
                            callees.append(
                                {
                                    "addr": hex(target),
                                    "name": func_name,
                                    "type": func_type,
                                }
                            )
                current_ea = idc.next_head(current_ea, func_end)

            unique_callee_tuples = {tuple(callee.items()) for callee in callees}
            unique_callees = [dict(callee) for callee in unique_callee_tuples]
            results.append({"addr": fn_addr, "callees": unique_callees})
        except Exception as e:
            results.append({"addr": fn_addr, "callees": None, "error": str(e)})

    return results


@tool
@idaread
def callers(
    addrs: Annotated[list[str] | str, "Function addresses to get callers for"],
) -> list[dict]:
    """Get all functions that call the specified functions"""
    addrs = normalize_list_input(addrs)
    results = []

    for fn_addr in addrs:
        try:
            callers = {}
            for caller_addr in idautils.CodeRefsTo(parse_address(fn_addr), 0):
                func = get_function(caller_addr, raise_error=False)
                if not func:
                    continue
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, caller_addr)
                if insn.itype not in [
                    idaapi.NN_call,
                    idaapi.NN_callfi,
                    idaapi.NN_callni,
                ]:
                    continue
                callers[func["addr"]] = func

            results.append({"addr": fn_addr, "callers": list(callers.values())})
        except Exception as e:
            results.append({"addr": fn_addr, "callers": None, "error": str(e)})

    return results


@tool
@idaread
def entrypoints() -> list[Function]:
    """Get entry points"""
    result = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        addr = ida_entry.get_entry(ordinal)
        func = get_function(addr, raise_error=False)
        if func is not None:
            result.append(func)
    return result


# ============================================================================
# Comprehensive Function Analysis
# ============================================================================


@tool
@idaread
def analyze_funcs(
    addrs: Annotated[list[str] | str, "Function addresses to comprehensively analyze"],
) -> list[FunctionAnalysis]:
    """Comprehensive function analysis: decompilation, xrefs, callees, strings, constants, blocks"""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)

            if not func:
                results.append(
                    FunctionAnalysis(
                        addr=addr,
                        name=None,
                        code=None,
                        asm=None,
                        xto=[],
                        xfrom=[],
                        callees=[],
                        callers=[],
                        strings=[],
                        constants=[],
                        blocks=[],
                        error="Function not found",
                    )
                )
                continue

            # Get basic blocks
            flowchart = idaapi.FlowChart(func)
            blocks = []
            for block in flowchart:
                blocks.append(
                    {
                        "start": hex(block.start_ea),
                        "end": hex(block.end_ea),
                        "type": block.type,
                    }
                )

            result = FunctionAnalysis(
                addr=addr,
                name=ida_funcs.get_func_name(func.start_ea),
                code=decompile_function_safe(ea),
                asm=get_assembly_lines(ea),
                xto=[
                    Xref(
                        addr=hex(x.frm),
                        type="code" if x.iscode else "data",
                        fn=get_function(x.frm, raise_error=False),
                    )
                    for x in idautils.XrefsTo(ea, 0)
                ],
                xfrom=get_xrefs_from_internal(ea),
                callees=get_callees(addr),
                callers=get_callers(addr),
                strings=extract_function_strings(ea),
                constants=extract_function_constants(ea),
                blocks=blocks,
                error=None,
            )
            results.append(result)
        except Exception as e:
            results.append(
                FunctionAnalysis(
                    addr=addr,
                    name=None,
                    code=None,
                    asm=None,
                    xto=[],
                    xfrom=[],
                    callees=[],
                    callers=[],
                    strings=[],
                    constants=[],
                    blocks=[],
                    error=str(e),
                )
            )
    return results


# ============================================================================
# Pattern Matching & Signature Tools
# ============================================================================


@tool
@idaread
def find_bytes(
    patterns: Annotated[
        list[str] | str, "Byte patterns to search for (e.g. '48 8B ?? ??')"
    ],
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for byte patterns in the binary (supports wildcards with ??)"""
    patterns = normalize_list_input(patterns)

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    for pattern in patterns:
        all_matches = []
        try:
            # Parse the pattern
            compiled = ida_bytes.compiled_binpat_vec_t()
            err = ida_bytes.parse_binpat_str(
                compiled, ida_ida.inf_get_min_ea(), pattern, 16
            )
            if err:
                results.append(
                    {
                        "pattern": pattern,
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                    }
                )
                continue

            # Search for all matches
            ea = ida_ida.inf_get_min_ea()
            while ea != idaapi.BADADDR:
                ea = ida_bytes.bin_search(
                    ea, ida_ida.inf_get_max_ea(), compiled, ida_bytes.BIN_SEARCH_FORWARD
                )
                if ea != idaapi.BADADDR:
                    all_matches.append(hex(ea))
                    ea += 1
        except Exception:
            pass

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )
    return results


@tool
@idaread
def find_insns(
    sequences: Annotated[
        list[list[str]] | list[str], "Instruction mnemonic sequences to search for"
    ],
    limit: Annotated[
        int, "Max matches per sequence (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for sequences of instruction mnemonics in the binary"""
    # Handle single sequence vs array of sequences
    if sequences and isinstance(sequences[0], str):
        sequences = [sequences]

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []

    for sequence in sequences:
        if not sequence:
            results.append(
                {
                    "sequence": sequence,
                    "matches": [],
                    "count": 0,
                    "cursor": {"done": True},
                }
            )
            continue

        all_matches = []
        # Scan all code segments
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                continue

            ea = seg.start_ea
            while ea < seg.end_ea:
                # Try to match sequence starting at ea
                match_ea = ea
                matched = True

                for expected_mnem in sequence:
                    insn = idaapi.insn_t()
                    if idaapi.decode_insn(insn, match_ea) == 0:
                        matched = False
                        break

                    actual_mnem = idc.print_insn_mnem(match_ea)
                    if actual_mnem != expected_mnem:
                        matched = False
                        break

                    match_ea = idc.next_head(match_ea, seg.end_ea)
                    if match_ea == idaapi.BADADDR:
                        matched = False
                        break

                if matched:
                    all_matches.append(hex(ea))

                ea = idc.next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "sequence": sequence,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )

    return results


# ============================================================================
# Control Flow Analysis
# ============================================================================


@tool
@idaread
def basic_blocks(
    addrs: Annotated[list[str] | str, "Function addresses to get basic blocks for"],
    max_blocks: Annotated[
        int, "Max basic blocks per function (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N blocks (default: 0)"] = 0,
) -> list[dict]:
    """Get control flow graph basic blocks for functions"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if max_blocks <= 0 or max_blocks > 10000:
        max_blocks = 10000

    results = []
    for fn_addr in addrs:
        try:
            ea = parse_address(fn_addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "addr": fn_addr,
                        "error": "Function not found",
                        "blocks": [],
                        "cursor": {"done": True},
                    }
                )
                continue

            flowchart = idaapi.FlowChart(func)
            all_blocks = []

            for block in flowchart:
                all_blocks.append(
                    BasicBlock(
                        start=hex(block.start_ea),
                        end=hex(block.end_ea),
                        size=block.end_ea - block.start_ea,
                        type=block.type,
                        successors=[hex(succ.start_ea) for succ in block.succs()],
                        predecessors=[hex(pred.start_ea) for pred in block.preds()],
                    )
                )

            # Apply pagination
            total_blocks = len(all_blocks)
            blocks = all_blocks[offset : offset + max_blocks]
            has_more = offset + max_blocks < total_blocks

            results.append(
                {
                    "addr": fn_addr,
                    "blocks": blocks,
                    "count": len(blocks),
                    "total_blocks": total_blocks,
                    "cursor": (
                        {"next": offset + max_blocks} if has_more else {"done": True}
                    ),
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": fn_addr,
                    "error": str(e),
                    "blocks": [],
                    "cursor": {"done": True},
                }
            )
    return results


@tool
@idaread
def find_paths(queries: list[PathQuery] | PathQuery) -> list[dict]:
    """Find execution paths between source and target addresses"""
    if isinstance(queries, dict):
        queries = [queries]
    results = []

    for query in queries:
        source = parse_address(query["source"])
        target = parse_address(query["target"])

        # Get containing function
        func = idaapi.get_func(source)
        if not func:
            results.append(
                {
                    "source": query["source"],
                    "target": query["target"],
                    "paths": [],
                    "reachable": False,
                    "error": "Source not in a function",
                }
            )
            continue

        # Build flow graph
        flowchart = idaapi.FlowChart(func)

        # Find source and target blocks
        source_block = None
        target_block = None
        for block in flowchart:
            if block.start_ea <= source < block.end_ea:
                source_block = block
            if block.start_ea <= target < block.end_ea:
                target_block = block

        if not source_block or not target_block:
            results.append(
                {
                    "source": query["source"],
                    "target": query["target"],
                    "paths": [],
                    "reachable": False,
                    "error": "Could not find basic blocks",
                }
            )
            continue

        # Simple BFS to find paths
        paths = []
        queue = [([source_block], {source_block.id})]

        while queue and len(paths) < 10:  # Limit paths
            path, visited = queue.pop(0)
            current = path[-1]

            if current.id == target_block.id:
                paths.append([hex(b.start_ea) for b in path])
                continue

            for succ in current.succs():
                if succ.id not in visited and len(path) < 20:  # Limit depth
                    queue.append((path + [succ], visited | {succ.id}))

        results.append(
            {
                "source": query["source"],
                "target": query["target"],
                "paths": paths,
                "reachable": len(paths) > 0,
                "error": None,
            }
        )

    return results


# ============================================================================
# Search Operations
# ============================================================================


@tool
@idaread
def find_crypt_constants(
    limit: Annotated[int, "Max matches per constant type (default: 100)"] = 100,
) -> list[dict]:
    """Identify common cryptographic constants (AES S-Boxes, MD5/SHA initializers, etc.)"""
    
    # Common crypto constants signatures
    # Format: (Name, Pattern string)
    CRYPTO_SIGNATURES = [
        # AES
        ("AES_Sbox", "63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76"),
        ("AES_InvSbox", "52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB"),
        ("AES_Te0", "C6 63 63 A5 F8 7C 7C 84 EE 77 77 99 F6 7B 7B 8D"),
        ("AES_Td0", "51 F4 A7 50 7E 41 65 53 1A 17 A4 C3 3A 27 5E 96"),
        
        # MD5
        ("MD5_Init", "01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10"), # A, B, C, D (Little Endian)
        ("MD5_K", "78 A4 6A D7 56 B7 C7 E8 DB 70 20 24 EE CE BD 45"), # First 4 constants
        
        # SHA-1
        ("SHA1_Init", "01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 F0 E1 D2 C3"), # A, B, C, D, E (Big Endian logic but byte sequence depends)
        # Actually SHA1 init is often separate dwords. Let's try byte sequence for common impls (e.g. OpenSSL)
        # h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0
        # Little Endian: 01 23 45 67 89 AB CD EF ...
        
        # SHA-256
        ("SHA256_K", "98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9"), # First 4 constants
        
        # RC4 (Look for 00..FF sequence, though common in other things too)
        # ("RC4_Sbox_Init", "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"), # Too generic?
        
        # Zlib / Deflate
        ("Zlib_Distance_Code", "00 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00"), # Common table start
    ]

    results = []
    
    # Pre-fetch min/max addresses
    min_ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()

    for name, pattern in CRYPTO_SIGNATURES:
        try:
            # Reuse _perform_binary_search logic directly? 
            # Or just use ida_search.find_binary since we have hex patterns
            
            curr_ea = min_ea
            count = 0
            matches = []
            
            while True:
                # Use idc.find_binary / ida_search.find_binary
                # Pattern is space-separated hex
                found_ea = idaapi.BADADDR
                
                if hasattr(idc, "find_binary"):
                    found_ea = idc.find_binary(curr_ea, idc.SEARCH_DOWN, pattern)
                elif hasattr(idc, "FindBinary"):
                    found_ea = idc.FindBinary(curr_ea, idc.SEARCH_DOWN, pattern)
                elif hasattr(ida_bytes, "bin_search"):
                     # Fallback
                     pt_obj = ida_bytes.compiled_binpat_vec_t()
                     ida_bytes.parse_binpat_str(pt_obj, curr_ea, pattern, 16)
                     res = ida_bytes.bin_search(curr_ea, max_ea, pt_obj, ida_bytes.BIN_SEARCH_FORWARD)
                     if isinstance(res, tuple):
                         found_ea = res[0]
                     else:
                         found_ea = res
                
                if found_ea == idaapi.BADADDR or found_ea >= max_ea:
                    break
                    
                matches.append(hex(found_ea))
                count += 1
                curr_ea = found_ea + 1
                
                if count >= limit:
                    break
            
            if matches:
                results.append({
                    "algorithm": name,
                    "matches": matches,
                    "count": count
                })
                
        except Exception as e:
            print(f"[MCP] Error searching for {name}: {e}")
            
    return results


@tool
@idaread
def get_function_complexity(
    addrs: Annotated[list[str] | str, "Function addresses to analyze"],
) -> list[dict]:
    """Calculate function complexity metrics (Cyclomatic Complexity, size, etc.)"""
    addrs = normalize_list_input(addrs)
    results = []
    
    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append({"addr": addr, "error": "Function not found"})
                continue
                
            # Get flow chart
            fc = idaapi.FlowChart(func)
            
            # Basic metrics
            num_blocks = fc.size
            num_instructions = 0
            num_edges = 0
            
            for block in fc:
                # Count instructions
                head = block.start_ea
                while head < block.end_ea:
                    num_instructions += 1
                    head = idc.next_head(head, block.end_ea)
                
                # Count edges (successors)
                num_edges += sum(1 for _ in block.succs())
            
            # Cyclomatic Complexity: E - N + 2P (P=1 for single function)
            # E = edges, N = nodes (blocks)
            cyclomatic = num_edges - num_blocks + 2
            
            func_name = ida_funcs.get_func_name(func.start_ea)
            
            results.append({
                "addr": hex(func.start_ea),
                "name": func_name,
                "metrics": {
                    "basic_blocks": num_blocks,
                    "instructions": num_instructions,
                    "edges": num_edges,
                    "cyclomatic_complexity": cyclomatic,
                    "size_bytes": func.size(),
                }
            })
            
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})
            
    return results


@tool
@idaread
def trace_argument(
    addr: Annotated[str, "Address of the function call instruction"],
    arg_index: Annotated[int, "Argument index (0-based)"],
) -> dict:
    """Trace the origin of a function argument (Experimental)"""
    # This requires Hex-Rays decompiler to be effective
    try:
        ea = parse_address(addr)
        
        # Decompile the function containing the call
        func = idaapi.get_func(ea)
        if not func:
            return {"error": "Address not in a function"}
            
        try:
            cfunc = ida_hexrays.decompile(func)
        except Exception:
            return {"error": "Decompilation failed"}
            
        if not cfunc:
            return {"error": "Decompilation failed"}
            
        # Find the call expression at 'ea'
        # This is tricky because one instruction might map to multiple C items
        # We need to traverse the C tree to find the call
        
        class CallFinder(ida_hexrays.ctree_visitor_t):
            def __init__(self, target_ea):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                self.target_ea = target_ea
                self.found_call = None
                
            def visit_expr(self, e):
                if e.op == ida_hexrays.cot_call and e.ea == self.target_ea:
                    self.found_call = e
                    return 1 # Stop
                return 0
                
        finder = CallFinder(ea)
        finder.apply_to(cfunc.body, None)
        
        if not finder.found_call:
            return {"error": "Could not locate call expression at address"}
            
        # Get argument expression
        args = finder.found_call.a
        if arg_index >= len(args):
            return {"error": f"Argument index {arg_index} out of bounds (count: {len(args)})"}
            
        arg_expr = args[arg_index]
        
        # Analyze the argument expression
        result = {
            "addr": hex(ea),
            "arg_index": arg_index,
            "expr_type": "unknown",
            "value": None,
            "sources": []
        }
        
        if arg_expr.op == ida_hexrays.cot_num:
            result["expr_type"] = "constant"
            result["value"] = hex(arg_expr.n.value(arg_expr.type))
            
        elif arg_expr.op == ida_hexrays.cot_obj:
            result["expr_type"] = "global"
            result["value"] = hex(arg_expr.obj_ea)
            result["name"] = ida_name.get_name(arg_expr.obj_ea)
            
        elif arg_expr.op == ida_hexrays.cot_str:
            result["expr_type"] = "string"
            result["value"] = arg_expr.string
            
        elif arg_expr.op == ida_hexrays.cot_var:
            result["expr_type"] = "variable"
            # Get variable info
            lvar = cfunc.get_lvars()[arg_expr.v.idx]
            result["name"] = lvar.name
            
            # Simple def-use trace (find where this var was last assigned)
            # This is complex in Python API, but we can try basic check
            # For now, just return the variable info
            
        else:
            result["expr_type"] = "complex"
            result["op_code"] = arg_expr.op
            result["pretty_print"] = str(arg_expr) # Need a way to print ctree item
            
        return result
        
    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def emulate_snippet(
    start_addr: Annotated[str, "Start address"],
    end_addr: Annotated[str, "End address (exclusive)"],
    initial_regs: Annotated[dict, "Initial register values (e.g. {'EAX': 0x1})"] = {},
    max_steps: Annotated[int, "Max instructions to execute"] = 1000,
) -> dict:
    """Emulate a code snippet using Unicorn Engine (if available)"""
    try:
        import unicorn
        from unicorn import x86_const
    except ImportError:
        return {"error": "Unicorn engine not installed in IDA Python environment"}
        
    try:
        start_ea = parse_address(start_addr)
        end_ea = parse_address(end_addr)
        
        # Detect arch
        info = idaapi.get_inf_structure()
        if info.procName != "metapc":
            return {"error": "Only x86/x64 supported for now"}
            
        is_64 = info.is_64bit()
        mode = unicorn.UC_MODE_64 if is_64 else unicorn.UC_MODE_32
        uc = unicorn.Uc(unicorn.UC_ARCH_X86, mode)
        
        # Map memory
        # We need to map the code segment and maybe data
        # For simplicity, let's map a 2MB chunk around start_ea
        page_size = 4096
        base = start_ea & ~(page_size - 1)
        size = 2 * 1024 * 1024 # 2MB
        
        uc.mem_map(base, size)
        
        # Read code from IDA and write to Unicorn
        code_bytes = ida_bytes.get_bytes(base, size)
        if code_bytes:
            uc.mem_write(base, code_bytes)
        else:
            return {"error": "Failed to read memory from IDA"}
            
        # Setup registers
        reg_map = {
            "EAX": x86_const.UC_X86_REG_EAX,
            "ECX": x86_const.UC_X86_REG_ECX,
            "EDX": x86_const.UC_X86_REG_EDX,
            "EBX": x86_const.UC_X86_REG_EBX,
            "ESP": x86_const.UC_X86_REG_ESP,
            "EBP": x86_const.UC_X86_REG_EBP,
            "ESI": x86_const.UC_X86_REG_ESI,
            "EDI": x86_const.UC_X86_REG_EDI,
            "RAX": x86_const.UC_X86_REG_RAX,
            "RCX": x86_const.UC_X86_REG_RCX,
            "RDX": x86_const.UC_X86_REG_RDX,
            "RBX": x86_const.UC_X86_REG_RBX,
            "RSP": x86_const.UC_X86_REG_RSP,
            "RBP": x86_const.UC_X86_REG_RBP,
            "RSI": x86_const.UC_X86_REG_RSI,
            "RDI": x86_const.UC_X86_REG_RDI,
        }
        
        for reg, val in initial_regs.items():
            if reg.upper() in reg_map:
                uc.reg_write(reg_map[reg.upper()], int(str(val), 0))
                
        # Setup stack if ESP/RSP not provided
        # Map a separate stack region
        stack_base = 0x7F000000
        stack_size = 0x100000
        uc.mem_map(stack_base, stack_size)
        
        if "ESP" not in initial_regs and "RSP" not in initial_regs:
            sp_reg = x86_const.UC_X86_REG_RSP if is_64 else x86_const.UC_X86_REG_ESP
            uc.reg_write(sp_reg, stack_base + stack_size - 8)
        
        # Run
        uc.emu_start(start_ea, end_ea, count=max_steps)
        
        # Capture final state
        final_regs = {}
        for r_name in (["RAX", "RBX", "RCX", "RDX"] if is_64 else ["EAX", "EBX", "ECX", "EDX"]):
            final_regs[r_name] = hex(uc.reg_read(reg_map[r_name]))
            
        return {
            "status": "success",
            "final_registers": final_regs
        }
        
    except Exception as e:
        return {"error": str(e)}


def _perform_binary_search(
    targets: list[str | int],
    limit: int = 1000,
    offset: int = 0,
    timeout: int = 30,
) -> list[dict]:
    """Helper to perform optimized binary search for strings"""
    results = []
    start_time = time.time()

    for pattern in targets:
        pattern_str = str(pattern)
        all_matches = []
        count = 0

        ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()

        # Prepare search encodings: ASCII and UTF-16LE
        encodings = []
        try:
            # 1. ASCII / UTF-8
            encodings.append(pattern_str.encode("utf-8"))
            # 2. UTF-16LE (Wide Char)
            encodings.append(pattern_str.encode("utf-16le"))
        except Exception:
            pass

        try:
            for encoded_bytes in encodings:
                # Check timeout
                if time.time() - start_time > timeout:
                    break

                # Build binary pattern string for IDA
                # Format: "XX XX XX ..."
                hex_pattern = " ".join([f"{b:02X}" for b in encoded_bytes])

                # Search using available method
                search_ea = ea
                while True:
                    if time.time() - start_time > timeout:
                        break

                    found_ea = idaapi.BADADDR

                    try:
                        if hasattr(idc, "find_binary"):
                            found_ea = idc.find_binary(search_ea, idc.SEARCH_DOWN, hex_pattern)
                        elif hasattr(idc, "FindBinary"):
                            found_ea = idc.FindBinary(search_ea, idc.SEARCH_DOWN, hex_pattern)
                        elif hasattr(ida_bytes, "bin_search"):
                            # Fallback to bin_search with compiled pattern if idc fails
                            pt_obj = ida_bytes.compiled_binpat_vec_t()
                            ida_bytes.parse_binpat_str(pt_obj, search_ea, hex_pattern, 16)
                            res = ida_bytes.bin_search(
                                search_ea, max_ea, pt_obj, ida_bytes.BIN_SEARCH_FORWARD
                            )
                            if isinstance(res, tuple):
                                found_ea = res[0]
                            else:
                                found_ea = res
                    except Exception as e:
                        print(f"[MCP-DEBUG] Search error: {e}")
                        break

                    search_ea = found_ea

                    if search_ea == idaapi.BADADDR:
                        break

                    if search_ea >= max_ea:
                        break

                    all_matches.append(hex(search_ea))
                    count += 1

                    if count >= 10000 + offset:
                        break

                    search_ea += 1

        except Exception as e:
            print(f"[MCP] bin_search error: {e}")

        # Deduplicate matches (in case ASCII and UTF-16 overlap, though unlikely for valid strings)
        # and sort them
        all_matches = sorted(list(set(all_matches)), key=lambda x: int(x, 16))

        # Apply pagination
        matches = all_matches[offset : offset + limit]
        has_more = offset + limit < len(all_matches) or (
            len(all_matches) >= 10000 + offset
        )

        # Check if we timed out
        timed_out = time.time() - start_time > timeout
        error_msg = "Search timed out, partial results returned" if timed_out else None

        results.append(
            {
                "query": pattern_str,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
                "error": error_msg,
            }
        )

        if timed_out:
            break

    return results


@tool
@idaread
def search(
    type: Annotated[
        str, "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'"
    ],
    targets: Annotated[
        list[str | int] | str | int, "Search targets (strings, integers, or addresses)"
    ],
    limit: Annotated[int, "Max matches per target (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
    timeout: Annotated[int, "Max search time in seconds (default: 30)"] = 30,
) -> list[dict]:
    """Search for patterns in the binary (strings, immediate values, or references)"""
    if not isinstance(targets, list):
        targets = [targets]

    # Enforce max limit to prevent token overflow
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    start_time = time.time()

    if type == "string":
        # Search for strings using binary search (fastest and most robust)
        # This bypasses IDA's text rendering engine which can cause deadlocks in headless mode
        # OPTIMIZED: O(file_size) binary scan
        
        results = _perform_binary_search(targets, limit, offset, timeout)

    elif type == "immediate":
        # Search for immediate values
        for value in targets:
            if isinstance(value, str):
                try:
                    value = int(value, 0)
                except ValueError:
                    value = 0

            all_matches = []
            try:
                ea = ida_ida.inf_get_min_ea()
                while ea < ida_ida.inf_get_max_ea():
                    result = ida_search.find_imm(ea, ida_search.SEARCH_DOWN, value)
                    if result[0] == idaapi.BADADDR:
                        break
                    all_matches.append(hex(result[0]))
                    ea = result[0] + 1
            except Exception:
                pass

            # Apply pagination
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)

            results.append(
                {
                    "query": value,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if has_more else {"done": True},
                    "error": None,
                }
            )

    elif type == "data_ref":
        # Find all data references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                all_matches = [hex(xref) for xref in idautils.DataRefsTo(target)]

                # Apply pagination
                if limit > 0:
                    matches = all_matches[offset : offset + limit]
                    has_more = offset + limit < len(all_matches)
                else:
                    matches = all_matches[offset:]
                    has_more = False

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if has_more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    elif type == "code_ref":
        # Find all code references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                all_matches = [hex(xref) for xref in idautils.CodeRefsTo(target, 0)]

                # Apply pagination
                if limit > 0:
                    matches = all_matches[offset : offset + limit]
                    has_more = offset + limit < len(all_matches)
                else:
                    matches = all_matches[offset:]
                    has_more = False

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if has_more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    else:
        results.append(
            {
                "query": None,
                "matches": [],
                "count": 0,
                "cursor": {"done": True},
                "error": f"Unknown search type: {type}",
            }
        )

    return results


@tool
@idaread
def find_insn_operands(
    patterns: list[InsnPattern] | InsnPattern,
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Find instructions with specific mnemonics and operand values"""
    if isinstance(patterns, dict):
        patterns = [patterns]

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    for pattern in patterns:
        all_matches = _find_insn_pattern(pattern)

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )
    return results


def _find_insn_pattern(pattern: dict) -> list[str]:
    """Internal helper to find instructions matching a pattern"""
    mnem = pattern.get("mnem", "").lower()
    op0_val = pattern.get("op0")
    op1_val = pattern.get("op1")
    op2_val = pattern.get("op2")
    any_val = pattern.get("op_any")

    matches = []

    # Scan all executable segments
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
            continue

        ea = seg.start_ea
        while ea < seg.end_ea:
            # Check mnemonic
            if mnem and idc.print_insn_mnem(ea).lower() != mnem:
                ea = idc.next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            # Check specific operand positions
            match = True
            if op0_val is not None:
                if idc.get_operand_value(ea, 0) != op0_val:
                    match = False

            if op1_val is not None:
                if idc.get_operand_value(ea, 1) != op1_val:
                    match = False

            if op2_val is not None:
                if idc.get_operand_value(ea, 2) != op2_val:
                    match = False

            # Check any operand
            if any_val is not None and match:
                found_any = False
                for i in range(8):
                    if idc.get_operand_type(ea, i) == idaapi.o_void:
                        break
                    if idc.get_operand_value(ea, i) == any_val:
                        found_any = True
                        break
                if not found_any:
                    match = False

            if match:
                matches.append(hex(ea))

            ea = idc.next_head(ea, seg.end_ea)
            if ea == idaapi.BADADDR:
                break

    return matches


# ============================================================================
# Export Operations
# ============================================================================


@tool
@idaread
def export_funcs(
    addrs: Annotated[list[str] | str, "Function addresses to export"],
    format: Annotated[
        str, "Export format: json (default), c_header, or prototypes"
    ] = "json",
) -> dict:
    """Export function data in various formats"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append({"addr": addr, "error": "Function not found"})
                continue

            func_data = {
                "addr": addr,
                "name": ida_funcs.get_func_name(func.start_ea),
                "prototype": get_prototype(func),
                "size": hex(func.end_ea - func.start_ea),
                "comments": get_all_comments(ea),
            }

            if format == "json":
                func_data["asm"] = get_assembly_lines(ea)
                func_data["code"] = decompile_function_safe(ea)
                func_data["xrefs"] = get_all_xrefs(ea)

            results.append(func_data)

        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    if format == "c_header":
        # Generate C header file
        lines = ["// Auto-generated by IDA Pro MCP", ""]
        for func in results:
            if "prototype" in func and func["prototype"]:
                lines.append(f"{func['prototype']};")
        return {"format": "c_header", "content": "\n".join(lines)}

    elif format == "prototypes":
        # Just prototypes
        prototypes = []
        for func in results:
            if "prototype" in func and func["prototype"]:
                prototypes.append(
                    {"name": func.get("name"), "prototype": func["prototype"]}
                )
        return {"format": "prototypes", "functions": prototypes}

    return {"format": "json", "functions": results}


# ============================================================================
# Graph Operations
# ============================================================================


@tool
@idaread
def callgraph(
    roots: Annotated[
        list[str] | str, "Root function addresses to start call graph traversal from"
    ],
    max_depth: Annotated[int, "Maximum depth for call graph traversal"] = 5,
) -> list[dict]:
    """Build call graph starting from root functions"""
    roots = normalize_list_input(roots)
    results = []

    for root in roots:
        try:
            ea = parse_address(root)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "root": root,
                        "error": "Function not found",
                        "nodes": [],
                        "edges": [],
                    }
                )
                continue

            nodes = {}
            edges = []
            visited = set()

            def traverse(addr, depth):
                if depth > max_depth or addr in visited:
                    return
                visited.add(addr)

                f = idaapi.get_func(addr)
                if not f:
                    return

                func_name = ida_funcs.get_func_name(f.start_ea)
                nodes[hex(addr)] = {
                    "addr": hex(addr),
                    "name": func_name,
                    "depth": depth,
                }

                # Get callees
                for item_ea in idautils.FuncItems(f.start_ea):
                    for xref in idautils.CodeRefsFrom(item_ea, 0):
                        callee_func = idaapi.get_func(xref)
                        if callee_func:
                            edges.append(
                                {
                                    "from": hex(addr),
                                    "to": hex(callee_func.start_ea),
                                    "type": "call",
                                }
                            )
                            traverse(callee_func.start_ea, depth + 1)

            traverse(ea, 0)

            results.append(
                {
                    "root": root,
                    "nodes": list(nodes.values()),
                    "edges": edges,
                    "max_depth": max_depth,
                    "error": None,
                }
            )

        except Exception as e:
            results.append({"root": root, "error": str(e), "nodes": [], "edges": []})

    return results


# ============================================================================
# Cross-Reference Matrix
# ============================================================================


@tool
@idaread
def xref_matrix(
    entities: Annotated[
        list[str] | str, "Addresses to build cross-reference matrix for"
    ],
) -> dict:
    """Build matrix showing cross-references between entities"""
    entities = normalize_list_input(entities)
    matrix = {}

    for source in entities:
        try:
            source_ea = parse_address(source)
            matrix[source] = {}

            for target in entities:
                if source == target:
                    continue

                target_ea = parse_address(target)

                # Count references from source to target
                count = 0
                for xref in idautils.XrefsFrom(source_ea, 0):
                    if xref.to == target_ea:
                        count += 1

                if count > 0:
                    matrix[source][target] = count

        except Exception:
            matrix[source] = {"error": "Failed to process"}

    return {"matrix": matrix, "entities": entities}


# ============================================================================
# String Analysis
# ============================================================================


@tool
@idaread
def analyze_strings(
    filters: list[StringFilter] | StringFilter,
    limit: Annotated[int, "Max matches per filter (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Analyze and filter strings in the binary"""
    if isinstance(filters, dict):
        filters = [filters]

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    
    # Pre-fetch min/max addresses for validation
    min_ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()

    for filt in filters:
        pattern = filt.get("pattern", "")
        min_length = filt.get("min_length", 0)
        
        # Optimize: If pattern is provided, use search() logic instead of iterating all strings
        if pattern and len(pattern) > 3 and pattern != "*": # Only use search for reasonably long patterns
             # Use the robust bin_search implementation via shared helper
             # This is much faster for finding specific strings than iterating all strings
             try:
                 print(f"[MCP-DEBUG] Optimizing strings query with search(): {pattern}")
                 # Directly call the helper, NOT the tool wrapper
                 search_results = _perform_binary_search(targets=[pattern], limit=limit, offset=offset, timeout=60)
                 
                 # Convert search results to analyze_strings format
                 final_matches = []
                 for res in search_results:
                     if res.get("error"):
                         continue
                     for m_addr_str in res.get("matches", []):
                         ea = int(m_addr_str, 16)
                         # Try to get string content at this address
                         try:
                             s_len = 0
                             s_content = pattern # Default to pattern
                             
                             # Try to detect actual string length and content
                             # This is a best-effort since we found a binary match
                             detected_str_type = ida_nalt.get_str_type(ea)
                             if detected_str_type:
                                 content = idc.get_strlit_contents(ea, -1, detected_str_type)
                                 if content:
                                     s_content = content.decode("utf-8", errors="replace")
                                     s_len = len(content)
                             
                             match = {
                                 "addr": hex(ea),
                                 "length": s_len,
                                 "string": s_content,
                                 "type": detected_str_type
                             }
                             
                             # Add xrefs
                             xrefs = [hex(x.frm) for x in idautils.XrefsTo(ea, 0)]
                             match["xrefs"] = xrefs
                             match["xref_count"] = len(xrefs)
                             
                             final_matches.append(match)
                         except:
                             pass
                             
                 results.append(
                    {
                        "filter": filt,
                        "matches": final_matches,
                        "count": len(final_matches),
                        "total_estimated": len(final_matches), # Accurate for search
                        "cursor": {"done": True}, # Search handles pagination internally but here we simplify
                    }
                 )
                 continue # Skip to next filter
             except Exception as e:
                 print(f"[MCP] Optimized search failed, falling back to iteration: {e}")

        # Fallback to iteration for short patterns or wildcard
        # Use idautils.Strings() generator directly instead of caching all
        # This is O(N) where N is number of strings in binary
        all_matches = []
        count = 0
        
        try:
            # Iterate strings
            for s in idautils.Strings():
                s_str = str(s)
                
                # Apply length filter
                if len(s_str) < min_length:
                    continue
                    
                # Apply pattern filter
                if pattern:
                    # Treat "*" as wildcard for "all"
                    if pattern == "*":
                        pass
                    # Simple case-insensitive containment
                    elif pattern.lower() not in s_str.lower():
                        continue
                
                # Build result object
                # Fix: idautils.Strings() returns StringItem which has strtype, not type
                s_type = getattr(s, "strtype", 0)
                
                match = {
                    "addr": hex(s.ea),
                    "length": s.length,
                    "string": s_str,
                    "type": s_type
                }
                
                # Add xref info (expensive operation, maybe make optional?)
                # For large binaries, resolving xrefs for EVERY string is very slow.
                # Let's only resolve xrefs for the paginated result?
                # BUT, the tool contract implies we return xrefs.
                # Optimization: Only get xref count first? No, idautils.XrefsTo is a generator.
                
                # Compromise: We collect all matches first (fast), then resolve xrefs only for the slice we return.
                all_matches.append(match)
                
                # Safety break to prevent OOM on huge binaries if no filter
                if len(all_matches) > 100000 and not pattern:
                     # If we have too many results and no specific pattern, stop to avoid memory issues
                     break

        except Exception as e:
            print(f"[MCP] Error iterating strings: {e}")

        # Apply pagination
        if limit > 0:
            matches_slice = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches_slice = all_matches[offset:]
            has_more = False

        # Enrich the slice with Xrefs (Lazy loading)
        final_matches = []
        for m in matches_slice:
            try:
                ea = int(m["addr"], 16)
                xrefs = [hex(x.frm) for x in idautils.XrefsTo(ea, 0)]
                m["xrefs"] = xrefs
                m["xref_count"] = len(xrefs)
                final_matches.append(m)
            except:
                m["xrefs"] = []
                m["xref_count"] = 0
                final_matches.append(m)

        results.append(
            {
                "filter": filt,
                "matches": final_matches,
                "count": len(final_matches), # Count of returned items
                "total_estimated": len(all_matches), # Total matches found
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )

    return results

import sys
import signal
import logging
import argparse
from pathlib import Path
import queue
import struct
import os
import bisect

logger = logging.getLogger(__name__)

def _align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    rem = value % alignment
    if rem == 0:
        return value
    return value + (alignment - rem)


class _MinidumpRange:
    __slots__ = ("start", "end", "file_off")

    def __init__(self, start: int, end: int, file_off: int) -> None:
        self.start = start
        self.end = end
        self.file_off = file_off


class _MinidumpModule:
    __slots__ = ("base", "size", "name")

    def __init__(self, base: int, size: int, name: str) -> None:
        self.base = base
        self.size = size
        self.name = name


def _parse_minidump_streams(path: str) -> tuple[list[_MinidumpRange], list[_MinidumpModule]]:
    with open(path, "rb") as f:
        hdr = f.read(32)
        if len(hdr) < 32:
            raise ValueError("DMP too small")
        sig, _ver, nstreams, dir_rva, _checksum, _tstamp = struct.unpack_from("<IIIIII", hdr, 0)
        _flags = struct.unpack_from("<Q", hdr, 24)[0]

        if sig != 0x504D444D:
            raise ValueError("Not a minidump (bad signature)")

        f.seek(dir_rva)
        dirs = f.read(nstreams * 12)
        if len(dirs) < nstreams * 12:
            raise ValueError("Truncated stream directory")

        streams: dict[int, tuple[int, int]] = {}
        for i in range(nstreams):
            stype, dsize, rva = struct.unpack_from("<III", dirs, i * 12)
            streams[stype] = (dsize, rva)

        modules: list[_MinidumpModule] = []
        if 4 in streams:
            dsize, rva = streams[4]
            f.seek(rva)
            blob = f.read(dsize)
            if len(blob) >= 4:
                count = struct.unpack_from("<I", blob, 0)[0]
                off = 4
                for _ in range(count):
                    if off + 108 > len(blob):
                        break
                    base = struct.unpack_from("<Q", blob, off + 0)[0]
                    size = struct.unpack_from("<I", blob, off + 8)[0]
                    name_rva = struct.unpack_from("<I", blob, off + 20)[0]
                    off += 108

                    if name_rva == 0:
                        name = ""
                    else:
                        cur = f.tell()
                        try:
                            f.seek(name_rva)
                            raw_len = f.read(4)
                            if len(raw_len) != 4:
                                name = ""
                            else:
                                name_len = struct.unpack("<I", raw_len)[0]
                                raw = f.read(name_len)
                                name = raw.decode("utf-16le", errors="ignore")
                        finally:
                            f.seek(cur)

                    modules.append(_MinidumpModule(base=base, size=size, name=name))

        ranges: list[_MinidumpRange] = []
        if 9 in streams:
            dsize, rva = streams[9]
            f.seek(rva)
            hdr2 = f.read(16)
            if len(hdr2) == 16:
                count = struct.unpack_from("<Q", hdr2, 0)[0]
                base_rva = struct.unpack_from("<Q", hdr2, 8)[0]
                desc = f.read(count * 16)
                if len(desc) == count * 16:
                    cur_data_off = base_rva
                    for i in range(count):
                        start = struct.unpack_from("<Q", desc, i * 16 + 0)[0]
                        size = struct.unpack_from("<Q", desc, i * 16 + 8)[0]
                        end = start + size
                        if size > 0:
                            ranges.append(_MinidumpRange(start=start, end=end, file_off=cur_data_off))
                            cur_data_off += size
        elif 5 in streams:
            dsize, rva = streams[5]
            f.seek(rva)
            blob = f.read(dsize)
            if len(blob) >= 4:
                count = struct.unpack_from("<I", blob, 0)[0]
                off = 4
                for _ in range(count):
                    if off + 16 > len(blob):
                        break
                    start = struct.unpack_from("<Q", blob, off + 0)[0]
                    data_size = struct.unpack_from("<I", blob, off + 8)[0]
                    data_rva = struct.unpack_from("<I", blob, off + 12)[0]
                    off += 16
                    if data_size > 0:
                        ranges.append(_MinidumpRange(start=start, end=start + data_size, file_off=data_rva))

        ranges.sort(key=lambda r: r.start)
        modules.sort(key=lambda m: m.base)
        return ranges, modules


def _read_minidump_bytes(path: str, ranges: list[_MinidumpRange], ea: int, size: int) -> list[tuple[int, bytes]]:
    if size <= 0 or not ranges:
        return []

    starts = [r.start for r in ranges]
    idx = bisect.bisect_right(starts, ea) - 1
    if idx < 0:
        idx = 0

    wanted_end = ea + size
    parts: list[tuple[int, bytes]] = []
    with open(path, "rb") as f:
        i = idx
        while i < len(ranges):
            r = ranges[i]
            if r.start >= wanted_end:
                break
            if r.end <= ea:
                i += 1
                continue

            read_start = max(ea, r.start)
            read_end = min(wanted_end, r.end)
            read_len = read_end - read_start
            if read_len <= 0:
                i += 1
                continue

            file_off = r.file_off + (read_start - r.start)
            f.seek(file_off)
            chunk = f.read(read_len)
            if chunk:
                parts.append((read_start, chunk))
            i += 1

    return parts


def _parse_pe_sections(pe_header: bytes) -> tuple[list[dict], bool]:
    if len(pe_header) < 0x100:
        return [], False
    if pe_header[0:2] != b"MZ":
        return [], False
    e_lfanew = struct.unpack_from("<I", pe_header, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 0x18 > len(pe_header):
        return [], False
    if pe_header[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return [], False
    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", pe_header, coff_off + 2)[0]
    opt_size = struct.unpack_from("<H", pe_header, coff_off + 16)[0]
    opt_off = coff_off + 20
    if opt_off + opt_size > len(pe_header):
        return [], False
    magic = struct.unpack_from("<H", pe_header, opt_off)[0]
    is_64 = magic == 0x20B
    sec_off = opt_off + opt_size
    sections = []
    for i in range(num_sections):
        sh_off = sec_off + i * 40
        if sh_off + 40 > len(pe_header):
            break
        name = pe_header[sh_off : sh_off + 8].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        vsize = struct.unpack_from("<I", pe_header, sh_off + 8)[0]
        vaddr = struct.unpack_from("<I", pe_header, sh_off + 12)[0]
        raw_size = struct.unpack_from("<I", pe_header, sh_off + 16)[0]
        ch = struct.unpack_from("<I", pe_header, sh_off + 36)[0]
        size = max(vsize, raw_size)
        if size == 0:
            continue
        sections.append({"name": name or f"sec{i}", "vaddr": vaddr, "size": size, "ch": ch})
    return sections, is_64


def _parse_pe_entrypoint(pe_header: bytes) -> tuple[int | None, int | None, bool]:
    if len(pe_header) < 0x100:
        return None, None, False
    if pe_header[0:2] != b"MZ":
        return None, None, False
    e_lfanew = struct.unpack_from("<I", pe_header, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 0x18 > len(pe_header):
        return None, None, False
    if pe_header[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None, None, False
    coff_off = e_lfanew + 4
    machine = struct.unpack_from("<H", pe_header, coff_off + 0)[0]
    opt_size = struct.unpack_from("<H", pe_header, coff_off + 16)[0]
    opt_off = coff_off + 20
    if opt_off + opt_size > len(pe_header) or opt_size < 0x20:
        return None, machine, False
    magic = struct.unpack_from("<H", pe_header, opt_off)[0]
    is_64 = magic == 0x20B
    entry_rva = struct.unpack_from("<I", pe_header, opt_off + 16)[0]
    if entry_rva == 0:
        return None, machine, is_64
    return int(entry_rva), machine, is_64


def _materialize_minidump_into_idb(path: str, *, max_total_bytes: int = 256 * 1024 * 1024) -> dict:
    import ida_auto
    import ida_bytes
    import ida_ida
    import ida_segment
    import idaapi
    import ida_funcs

    ranges, modules = _parse_minidump_streams(path)
    if not ranges:
        return {"ok": False, "error": "No memory ranges found in minidump", "segments_added": 0}

    wants_64bit = any(int(m.base) > 0xFFFFFFFF for m in modules)
    if wants_64bit:
        try:
            if hasattr(ida_ida, "inf_set_app_bitness"):
                ida_ida.inf_set_app_bitness(2)
        except Exception:
            pass
        try:
            import idc

            if hasattr(idc, "set_inf_attr") and hasattr(idc, "get_inf_attr"):
                lflags = idc.get_inf_attr(getattr(idc, "INF_LFLAGS", 0))
                lflg_64 = getattr(idc, "LFLG_64BIT", 0)
                if lflg_64:
                    idc.set_inf_attr(getattr(idc, "INF_LFLAGS", 0), lflags | lflg_64)
        except Exception:
            pass

    bytes_budget = max_total_bytes
    segs_added = 0
    wrote_any = False
    seeded_funcs = 0
    seeded_strings = 0
    added_segments: list[tuple[int, int, int]] = []

    def _get_bitness() -> int:
        try:
            return 2 if bool(ida_ida.inf_is_64bit()) else 1
        except Exception:
            try:
                return 2 if bool(idaapi.get_inf_structure().is_64bit()) else 1
            except Exception:
                return 1

    def add_segment(start: int, end: int, name: str, sclass: str, perm: int) -> bool:
        nonlocal segs_added
        if start >= end:
            return False
        existing = ida_segment.getseg(start)
        if existing is not None:
            if existing.start_ea <= start and existing.end_ea >= end:
                try:
                    existing.perm = perm
                    ida_segment.update_segm(existing)
                except Exception:
                    pass
                added_segments.append((start, end, perm))
                return True
            return False

        try:
            seg = ida_segment.segment_t()
            seg.start_ea = start
            seg.end_ea = end
            seg.bitness = _get_bitness()
            seg.perm = perm
            ok = ida_segment.add_segm_ex(seg, name, sclass, 0)
        except Exception:
            ok = False

        if not ok:
            return False
        segs_added += 1
        added_segments.append((start, end, perm))
        return True

    def write_range(start: int, end: int) -> None:
        nonlocal bytes_budget, wrote_any
        if bytes_budget <= 0:
            return
        size = end - start
        if size <= 0:
            return

        for part_ea, part_data in _read_minidump_bytes(path, ranges, start, size):
            if bytes_budget <= 0:
                break
            if not part_data:
                continue
            if len(part_data) > bytes_budget:
                part_data = part_data[:bytes_budget]
            ida_bytes.put_bytes(part_ea, part_data)
            bytes_budget -= len(part_data)
            wrote_any = True

    def unique_seg_name(base_name: str) -> str:
        base_name = (base_name or "seg").replace(":", "_").replace("!", "_")
        base_name = base_name[:30]
        name = base_name
        i = 1
        while ida_segment.get_segm_by_name(name) is not None:
            suffix = f"_{i}"
            name = (base_name[: (30 - len(suffix))] + suffix) if len(base_name) > len(suffix) else (base_name + suffix)
            i += 1
        return name

    created_any = False
    def _module_key(m: _MinidumpModule) -> tuple[int, int, int]:
        base_name = os.path.basename(m.name).lower() if m.name else ""
        is_exe = 1 if base_name.endswith(".exe") else 2
        has_name = 0 if base_name else 1
        return (is_exe, has_name, int(m.base))

    try:
        max_modules = int(os.environ.get("IDA_MCP_DMP_MAX_MODULES", "8"))
    except Exception:
        max_modules = 8
    if max_modules < 0:
        max_modules = 0

    processed_modules = 0
    primary_mod_base: int | None = None
    primary_mod_name: str | None = None
    primary_mod_entry: int | None = None
    primary_machine: int | None = None
    primary_is_64 = wants_64bit

    for mod in sorted(modules, key=_module_key):
        if bytes_budget <= 0:
            break
        if mod.size <= 0:
            continue
        if max_modules and processed_modules >= max_modules:
            break

        mod_base = int(mod.base)
        mod_end = mod_base + int(mod.size)
        mod_basename = os.path.basename(mod.name) if mod.name else f"mod_{mod_base:x}"

        header_parts = _read_minidump_bytes(path, ranges, mod_base, 0x1000)
        header_bytes = bytearray()
        if header_parts and header_parts[0][0] == mod_base:
            header_bytes = bytearray(header_parts[0][1])
            if len(header_bytes) < 0x1000:
                header_bytes.extend(b"\x00" * (0x1000 - len(header_bytes)))

        if primary_mod_base is None:
            primary_mod_base = mod_base
            primary_mod_name = mod_basename
            entry_rva, machine, is_64 = _parse_pe_entrypoint(bytes(header_bytes)) if header_bytes else (None, None, wants_64bit)
            primary_machine = machine
            primary_is_64 = bool(is_64)
            if entry_rva is not None:
                primary_mod_entry = mod_base + int(entry_rva)

        sections, _is_64 = _parse_pe_sections(bytes(header_bytes)) if header_bytes else ([], False)
        if sections:
            sections.sort(key=lambda s: ((s["ch"] & 0x20000000) == 0, s["vaddr"]))
            for sec in sections:
                start = mod_base + int(sec["vaddr"])
                end = start + int(sec["size"])
                end = _align_up(end, 0x1000)
                ch = int(sec["ch"])
                perm = 0
                if ch & 0x40000000:
                    perm |= ida_segment.SEGPERM_READ
                if ch & 0x80000000:
                    perm |= ida_segment.SEGPERM_WRITE
                if ch & 0x20000000:
                    perm |= ida_segment.SEGPERM_EXEC
                if perm == 0:
                    perm = ida_segment.SEGPERM_READ

                sclass = "CODE" if (perm & ida_segment.SEGPERM_EXEC) else "DATA"
                seg_name = unique_seg_name(f"{mod_basename}.{sec['name']}")
                if add_segment(start, min(end, mod_end), seg_name, sclass, perm):
                    created_any = True
                    write_range(start, min(end, mod_end))
        else:
            seg_name = unique_seg_name(mod_basename)
            perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC
            end = _align_up(mod_end, 0x1000)
            if add_segment(mod_base, end, seg_name, "CODE", perm):
                created_any = True
                write_range(mod_base, end)
        processed_modules += 1

    if primary_mod_entry is not None:
        try:
            idaapi.set_processor_type("metapc", idaapi.SETPROC_LOADER)
        except Exception:
            pass
        try:
            import idc

            if primary_is_64 and hasattr(idc, "set_inf_attr"):
                try:
                    idc.set_inf_attr(getattr(idc, "INF_START_IP", 0), primary_mod_entry)
                except Exception:
                    pass
        except Exception:
            pass

        try:
            import idc

            if hasattr(idc, "create_insn"):
                idc.create_insn(primary_mod_entry)
        except Exception:
            pass
        try:
            ida_funcs.add_func(primary_mod_entry)
            seeded_funcs += 1
        except Exception:
            pass

    if added_segments and bytes_budget > 0:
        try:
            import idc
        except Exception:
            idc = None

        try:
            max_scan = int(os.environ.get("IDA_MCP_DMP_STRING_SCAN_BYTES", str(4 * 1024 * 1024)))
        except Exception:
            max_scan = 4 * 1024 * 1024
        if max_scan < 0:
            max_scan = 0

        remaining_scan = max_scan
        for seg_start, seg_end, perm in added_segments:
            if remaining_scan <= 0 or seeded_strings >= 50:
                break
            if perm & ida_segment.SEGPERM_EXEC:
                continue
            seg_size = seg_end - seg_start
            if seg_size <= 0:
                continue
            to_read = min(seg_size, remaining_scan)
            blob = ida_bytes.get_bytes(seg_start, to_read)
            if not blob:
                continue

            i = 0
            while i < len(blob) and seeded_strings < 50:
                b = blob[i]
                if 0x20 <= b <= 0x7E:
                    j = i
                    while j < len(blob) and 0x20 <= blob[j] <= 0x7E:
                        j += 1
                    if j < len(blob) and blob[j] == 0 and (j - i) >= 6:
                        ea = seg_start + i
                        length = j - i + 1
                        ok = False
                        if idc is not None:
                            try:
                                ok = bool(idc.create_strlit(ea, ea + length))
                            except TypeError:
                                try:
                                    ok = bool(idc.create_strlit(ea, length))
                                except Exception:
                                    ok = False
                            except Exception:
                                ok = False
                        if ok:
                            seeded_strings += 1
                            i = j + 1
                            continue
                    i = j + 1
                    continue

                if (i + 1) < len(blob) and 0x20 <= b <= 0x7E and blob[i + 1] == 0:
                    j = i
                    while (j + 1) < len(blob) and 0x20 <= blob[j] <= 0x7E and blob[j + 1] == 0:
                        j += 2
                    if (j + 1) < len(blob) and blob[j] == 0 and blob[j + 1] == 0 and ((j - i) // 2) >= 6:
                        ea = seg_start + i
                        length = (j - i) + 2
                        ok = False
                        if idc is not None:
                            try:
                                ok = bool(idc.create_strlit(ea, ea + length))
                            except TypeError:
                                try:
                                    ok = bool(idc.create_strlit(ea, length))
                                except Exception:
                                    ok = False
                            except Exception:
                                ok = False
                        if ok:
                            seeded_strings += 1
                            i = j + 2
                            continue
                    i = j + 2
                    continue

                i += 1

            remaining_scan -= to_read
        try:
            idaapi.build_strlist()
        except Exception:
            pass

    if not created_any and bytes_budget > 0:
        for r in ranges[:256]:
            if bytes_budget <= 0:
                break
            start = int(r.start)
            end = int(r.end)
            if start == 0 or start >= end:
                continue
            seg_name = unique_seg_name(f"mem_{start:x}")
            if add_segment(start, end, seg_name, "DATA", ida_segment.SEGPERM_READ):
                created_any = True
                write_range(start, end)

    if created_any or wrote_any:
        try:
            ida_auto.enable_auto(True)
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                if seg is None:
                    continue
                ida_auto.plan_range(seg.start_ea, seg.end_ea)
        except Exception:
            pass

    return {
        "ok": True,
        "segments_added": segs_added,
        "bytes_loaded": max_total_bytes - bytes_budget,
        "seeded_functions": seeded_funcs,
        "seeded_strings": seeded_strings,
        "primary_module": primary_mod_name or "",
        "primary_entry": hex(primary_mod_entry) if primary_mod_entry is not None else "",
    }


def _unload_package(package_name: str) -> None:
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


def _prefer_local_src() -> None:
    src_dir = str(Path(__file__).resolve().parent.parent)
    if not sys.path or sys.path[0] != src_dir:
        if src_dir in sys.path:
            sys.path.remove(src_dir)
        sys.path.insert(0, src_dir)
    _unload_package("ida_pro_mcp")
    _unload_package("ida_mcp")


def valid_path(p):
    # Remove surrounding quotes if present (IDA -S might pass them literally)
    s = str(p).strip('"\'')
    return Path(s)


def _detect_execution_mode():
    has_idapro = False
    is_native = False
    idaapi = None
    idapro = None

    try:
        import idaapi as _idaapi

        idaapi = _idaapi
        if _idaapi.get_root_filename():
            is_native = True
    except ImportError:
        pass

    if not is_native:
        try:
            import idapro as _idapro

            idapro = _idapro
            has_idapro = True
        except ImportError:
            try:
                import idaapi as _idaapi

                idaapi = _idaapi
                is_native = True
            except ImportError:
                print(
                    "Error: Could not load idaapi or idapro. Ensure you are running this with idalib or inside IDA."
                )
                sys.exit(1)

    return has_idapro, is_native, idaapi, idapro


def main():
    _prefer_local_src()
    has_idapro, is_native, idaapi, idapro = _detect_execution_mode()
    import ida_auto
    from ida_pro_mcp.ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler

    parser = argparse.ArgumentParser(description="MCP server for IDA Pro via idalib")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to listen on, default: 127.0.0.1",
    )
    parser.add_argument(
        "--port", type=int, default=8745, help="Port to listen on, default: 8745"
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)"
    )
    parser.add_argument(
        "--auto-analysis", 
        action="store_true", 
        default=False,
        help="Enable IDA auto-analysis on startup (default: False)"
    )
    parser.add_argument(
        "--loader",
        type=str,
        default=None,
        help="Specific IDA loader to use (e.g. windmp)"
    )
    parser.add_argument(
        "input_path", type=valid_path, nargs='?', help="Path to the input file to analyze."
    )
    
    # Parse args. In native IDA, use parse_known_args to avoid choking on IDA flags if any leak through.
    args, unknown = parser.parse_known_args()
    
    if unknown:
        logger.warning(f"Unknown arguments ignored: {unknown}")
    
    import os
    env_host = os.environ.get("IDA_MCP_HOST")
    env_port = os.environ.get("IDA_MCP_PORT")
    env_auto_analysis = os.environ.get("IDA_MCP_AUTO_ANALYSIS")
    env_loader = os.environ.get("IDA_MCP_LOADER")
    env_dmp_auto_start_debugger = os.environ.get("IDA_MCP_DMP_AUTO_START_DEBUGGER")
    if env_host:
        args.host = env_host
    if env_port:
        try:
            args.port = int(env_port)
        except ValueError:
            pass
    if env_auto_analysis == "1":
        args.auto_analysis = True
    if env_loader and not args.loader:
        args.loader = env_loader

    loader_arg = None
    if args.loader:
        # IDA argument format: -T<loader>
        loader_arg = f"-T{args.loader}"
        logger.info(f"Injecting loader argument: {loader_arg}")

    if has_idapro and not is_native:
        if args.verbose:
            log_level = logging.DEBUG
            idapro.enable_console_messages(True)
        else:
            log_level = logging.INFO
            idapro.enable_console_messages(False)
            
        if not args.input_path:
            print("Error: Input path is required when running in idalib mode.")
            sys.exit(1)
    else:
        # Native IDA
        log_level = logging.DEBUG if args.verbose else logging.INFO

    logging.basicConfig(level=log_level)

    # reset logging levels that might be initialized in idapythonrc.py
    # which is evaluated during import of idalib.
    logging.getLogger().setLevel(log_level)

    if args.input_path and not args.input_path.exists():
        # In native IDA, the file is already open, but we check anyway.
        # Note: In native IDA, input_path argument is still required by parser to know what we are working on.
        if has_idapro and not is_native:
             raise FileNotFoundError(f"Input file not found: {args.input_path}")
        else:
             logger.warning(f"Input file path provided {args.input_path} but running in native IDA.")

    # TODO: add a tool for specifying the idb/input file (sandboxed)
    if args.input_path:
        logger.info("opening database: %s", args.input_path)
    
    from ida_pro_mcp.ida_mcp import sync
    sync.HEADLESS_MODE = True
    
    # We must ensure IDAlib is properly initialized.
    if has_idapro and not is_native:
        try:
            # Revert: use simple string conversion as resolve() might cause issues on Windows
            # OPTIMIZATION: Use --auto-analysis flag to control behavior. 
            # Default is False to prevent infinite analysis loops / high memory usage on malware.
            ret_code = idapro.open_database(str(args.input_path), run_auto_analysis=args.auto_analysis, args=loader_arg)
            if ret_code != 0:
                logger.error(f"idapro.open_database returned code {ret_code}. Failed to open database.")
                # If we can't open the DB, the MCP server is useless. Exit.
                sys.exit(1)
        except OSError as e:
            # Catch the specific access violation if possible, or just log critical error
            logger.critical(f"Critical error opening database: {e}")
            logger.critical("This often happens if the input file format is not recognized or IDA loader crashes.")
            sys.exit(1)

        logger.debug("idalib: database opened, analysis running in background...")
    else:
        logger.info("Running inside native IDA. Database should be already open.")
        if args.auto_analysis:
            try:
                import ida_nalt

                input_path = ida_nalt.get_input_file_path() or ""
                is_dmp = input_path.lower().endswith(".dmp") or (args.loader or "").lower() == "windmp"
            except Exception:
                is_dmp = (args.loader or "").lower() == "windmp"

            if not is_dmp:
                logger.info("Triggering auto-analysis...")
                ida_auto.enable_auto(True)
                ida_auto.plan_range(0, 0xFFFFFFFFFFFFFFFF)

    # OPTIMIZATION: Do NOT block on auto_wait(). 
    # This allows the MCP server to start immediately while IDA analyzes in the background.
    # ida_auto.auto_wait() 

    # Setup signal handlers to ensure IDA database is properly closed on shutdown.
    # When a signal arrives, our handlers execute first, allowing us to close the
    # IDA database cleanly before the process terminates.
    def cleanup_and_exit(signum, frame):
        logger.info("Closing IDA database...")
        if has_idapro and not is_native:
            idapro.close_database()
            logger.info("IDA database closed.")
        else:
             logger.info("Running in native mode, skipping manual DB close.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    MCP_SERVER.serve(
        host=args.host,
        port=args.port,
        background=True,
        request_handler=IdaMcpHttpRequestHandler,
    )

    try:
        import ida_nalt
        import ida_dbg
        import ida_segment

        input_path = ida_nalt.get_input_file_path() or ""
        is_dmp = input_path.lower().endswith(".dmp") or (args.loader or "").lower() == "windmp"
        if is_dmp:
            def _auto_materialize_dmp():
                try:
                    should_materialize = ida_segment.get_segm_qty() == 0
                    if not should_materialize:
                        try:
                            import ida_ida

                            max_ea = int(ida_ida.inf_get_max_ea())
                            _, mods = _parse_minidump_streams(input_path)
                            if mods:
                                max_mod_end = max(
                                    int(m.base) + int(m.size)
                                    for m in mods
                                    if int(m.size) > 0
                                )
                                if max_ea <= max_mod_end:
                                    should_materialize = True
                        except Exception:
                            pass

                    if should_materialize:
                        result = _materialize_minidump_into_idb(input_path)
                        logger.info("Materialized minidump into IDB: %s", result)
                except Exception:
                    logger.exception("Failed to materialize minidump into IDB")

            sync.HEADLESS_QUEUE.put(_auto_materialize_dmp)

        if is_dmp and not ida_dbg.is_debugger_on():
            def _auto_start_dbg():
                ok = idaapi.start_process("", "", "")
                logger.info("Auto-start debugger for DMP returned: %s", ok)
                if ok == 1:
                    try:
                        import ida_idd

                        ida_dbg.enable_manual_regions(True)
                        existing = ida_dbg.get_manual_regions()
                        if not existing:
                            infos = ida_idd.meminfo_vec_t()
                            info = ida_idd.memory_info_t()
                            info.start_ea = 0
                            is_64bit = False
                            try:
                                import ida_ida

                                inf = ida_ida.inf_get_inf_structure()
                                is_64bit = bool(inf.is_64bit())
                            except Exception:
                                is_64bit = False
                            info.end_ea = (
                                0xFFFFFFFFFFFFFFFE
                                if is_64bit
                                else 0xFFFFFFFE
                            )
                            info.name = "MEMORY"
                            info.sclass = "UNK"
                            info.sbase = 0
                            info.bitness = 2 if is_64bit else 1
                            info.perm = 7
                            infos.push_back(info)
                            ida_dbg.set_manual_regions(infos)
                            logger.info("Configured manual memory regions for DMP")
                            if hasattr(ida_dbg, "invalidate_dbgmem_config"):
                                ida_dbg.invalidate_dbgmem_config()
                    except Exception:
                        logger.exception("Failed to configure manual memory regions for DMP")
                if args.auto_analysis:
                    ida_auto.enable_auto(True)
                    try:
                        import ida_segment

                        for i in range(ida_segment.get_segm_qty()):
                            seg = ida_segment.getnseg(i)
                            if seg is None:
                                continue
                            ida_auto.plan_range(seg.start_ea, seg.end_ea)
                    except Exception:
                        logger.exception("Failed to schedule auto-analysis ranges after DMP debugger start")

            sync.HEADLESS_QUEUE.put(_auto_start_dbg)
    except Exception:
        logger.exception("Failed to schedule DMP debugger auto-start")
    
    while True:
        try:
            task = sync.HEADLESS_QUEUE.get(timeout=0.1)
        except queue.Empty:
            continue
        try:
            task()
        except Exception:
            logger.exception("Error running headless task")


if __name__ == "__main__":
    main()

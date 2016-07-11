#This plugin is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# This plugin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.

"""
@author:       Alpha Abdoulaye
@license:      GNU General Public License 2.0
@contact:      alpha@lse.epita.fr
"""

import volatility.utils as utils
import volatility.commands as commands
import volatility.scan as scan
import string

from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex
from volatility import debug

class SymbolsCheck(scan.ScannerCheck):

    def __init__(self, address_space, patterns, step):
        super(SymbolsCheck, self).__init__(address_space)
        self.patterns = patterns
        self.step = step

    def check(self, _offset):
        for pattern in self.patterns:
            if pattern in str(self.address_space.zread(_offset, self.step)):
                return True

        return False

    def skip(self, data, offset):
        return self.step

class SymbolsScanner(scan.BaseScanner):
    def __init__(self, patterns, step):
        super(SymbolsScanner, self).__init__()
        self.checks = [("SymbolsCheck", {'patterns': patterns, 'step': step})]

class FindKernelSymbols(commands.Command):
    scan_start = 0x0
    scan_size = 0x10000000
    symtab_size = 0x100000
    step = 100
    
    vaddr = 0x0
    vabase_x86 = 0xC0000000
    vabase_x86_64 = 0xffffffff80000000
    header = False
    patterns = ["init_task", ("swapper" + "\x00" * 4)]
    unknown_type = "?"

    swapper_pg_dir = 0x0
    
    def calculate(self):
        address_space = utils.load_as(self._config, astype='physical')
        self.checkArch(address_space)
            
        scanner = SymbolsScanner(self.patterns, self.step)
        syms_end = False
        for address in scanner.scan(address_space, self.scan_start, self.scan_size):
            for pattern in self.patterns:
                syms_offset = str(address_space.zread(address, self.step)).find(pattern)
                if syms_offset == -1:
                    continue
                syms_start = address + syms_offset

                if pattern == self.patterns[1]:
                    if self.swapper_pg_dir == 0x0:
                        self.swapper_pg_dir = self.vaddr + syms_start
                else:
                    if syms_end:
                        break #TODO: choose best candidate
                    syms_strings = str(address_space.zread(syms_start, self.symtab_size))

                    symbols_format = string.ascii_letters + string.digits + "_"

                    syms_scan = SymbolsScanner(["\0"], 1)
                    yield self.vaddr + syms_start, self.unknown_type, self.patterns[0]
            
                    for sym_addr in syms_scan.scan(address_space, syms_start, self.symtab_size):
                        symbols_end = syms_strings[(sym_addr - syms_start) + 1:]

                        sym_string = symbols_end[:symbols_end.find('\0')]
                        if sym_string == "":
                            syms_end = True
                        for c in sym_string:
                            if c not in symbols_format:
                                syms_end = True
                                break
                        if syms_end:
                            break
                        yield self.vaddr + sym_addr, self.unknown_type, sym_string

    def checkArch(self, address_space):
        magic_32 = ["\x7F\x45\x4C\x46\x01"]
        magic_64 = ["\x7F\x45\x4C\x46\x02"]
        elf_step = 20000

        bin_x86 = 0
        bin_x86_64 = 0

        scanner = SymbolsScanner(magic_64, elf_step)
        for found in scanner.scan(address_space, self.scan_start, self.scan_size):
            bin_x86_64 += 1
            
        scanner = SymbolsScanner(magic_32, elf_step)
        for found in scanner.scan(address_space, self.scan_start, self.scan_size):
            bin_x86 += 1

        self.vaddr = self.vabase_x86_64 if bin_x86_64 > bin_x86 else self.vabase_x86

    def generator(self, data):
        for address, sym_type, name in data:
            yield (0, [Address(address), str(sym_type), str(name)])

    def unified_output(self, data):
        return TreeGrid([("Address", Address),
                         ("Type", str),
                         ("Name", str)],
                        self.generator(data))

    def fmt(self, address):
        addr = hex(address)[2:]
        if self.vaddr != self.vabase_x86:
            addr = addr[:len(addr)-1]
        return addr

    def format_address(self, address):
        return "0" * (len(self.fmt(self.vaddr)) - len(self.fmt(address))) + self.fmt(address)
     
    def output_line(self, outfd, outfile, address, symbol_type, name):
        self.table_row(outfd, address, symbol_type, name)

        outfile.write(address)
        outfile.write(" ")
        outfile.write(symbol_type)
        outfile.write(" ")
        outfile.write(name)
        outfile.write("\n")
        
    def write_first_symbols(self, outfd, outfile):
        init_sym = "A"
        if self.vaddr == self.vabase_x86_64:
            self.output_line(outfd, outfile, self.format_address(self.vaddr), self.unknown_type, "_stext")
        else:
            self.output_line(outfd, outfile, self.format_address(0x100000), init_sym, "phys_startup_32")
            self.output_line(outfd, outfile, self.format_address(self.vaddr), "T", "_text")

    def write_last_symbols(self, outfd, outfile):
        init_sym = "B"
        if self.vaddr == self.vabase_x86:
            self.output_line(outfd, outfile, self.format_address(self.swapper_pg_dir), init_sym, "swapper_pg_dir")
        else:
            self.output_line(outfd, outfile, self.format_address(0xc03bc000), init_sym, "init_level4_pgt")
    
    def render_text(self, outfd, data):
        print("Generating Symbols table...")
        self.table_header(outfd, [("Address", "20"),
                                  ("Type", "5"),
                                  ("Symbol", "32")])

        map_file_name = "System.map-unknown.version-generic"
        map_file = open(map_file_name, "w+")

        for address, sym_type, name in data:
            if not self.header:
                self.write_first_symbols(outfd, map_file)
                self.header = True
            self.output_line(outfd, map_file, self.format_address(address), sym_type, name)
        self.write_last_symbols(outfd, map_file)

        map_file.close()
        print(" \n+++ Generated System.map file: " + map_file_name + " +++")

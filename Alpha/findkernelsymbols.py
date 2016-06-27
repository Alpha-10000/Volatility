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
    step = 1000
    
    vaddr = 0x0
    patterns = ["init_task"]
    unknown_type = "?"

    def calculate(self):
        address_space = utils.load_as(self._config, astype='physical')

        self.checkArch(address_space)
        scanner = SymbolsScanner(self.patterns, self.step)
        for address in scanner.scan(address_space, self.scan_start, self.scan_size):
            syms_offset = str(address_space.zread(address, self.step)).find(self.patterns[0])
            syms_start = address + syms_offset
            syms_strings = str(address_space.zread(syms_start, self.symtab_size))

            symbols_format = string.ascii_letters + string.digits + "_"
            syms_end = False

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
            break #TODO: choose best candidate

    def checkArch(self, address_space):
        magic_32 = ["\x7F\x45\x4C\x46\x01"]
        magic_64 = ["\x7F\x45\x4C\x46\x02"]
        elf_step = 100

        bin_x86 = 0
        bin_x86_64 = 0

        scanner = SymbolsScanner(magic_64, elf_step)
        for found in scanner.scan(address_space, self.scan_start, self.scan_size):
            bin_x86_64 += 1
            
        scanner = SymbolsScanner(magic_32, elf_step)
        for found in scanner.scan(address_space, self.scan_start, self.scan_size):
            bin_x86 += 1

        self.vaddr = 0xffffffff80000000 if bin_x86_64 > bin_x86 else 0xC0000000
    def generator(self, data):
        for address, sym_type, name in data:
            yield (0, [Address(address), str(sym_type), str(name)])

    def unified_output(self, data):
        return TreeGrid([("Address", Address),
                         ("Type", str),
                         ("Name", str)],
                        self.generator(data))

    def format_address(self, address):
        addr = hex(address)[2:]
        if self.vaddr != 0xC0000000:
            addr = addr[:len(str(addr))-1]
        return addr

    def generate_file(self, data):
        map_file_name = "System.map-unknown.version-generic"
        map_file = open(map_file_name, "w+")
        for address, sym_type, name in data:
            addr = self.format_address(address)
            map_file.write(addr)
            map_file.write(" ")
            map_file.write(sym_type)
            map_file.write(" ")
            map_file.write(name)
            map_file.write("\n")
        map_file.close()

    def render_text(self, outfd, data):
        print("Generating Symbols table...")

        ## Uncomment to generate System.map file
        # self.generate_file(data)

        self.table_header(outfd, [("Address", "20"),
                                  ("Type", "5"),
                                  ("Symbol", "32")])
        for addr, sym_type, name in data:
            self.table_row(outfd, self.format_address(addr), sym_type, name)


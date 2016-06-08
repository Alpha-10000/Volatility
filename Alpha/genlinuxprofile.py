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
@organization: LSE (lse.epita.fr)
"""

import volatility.utils as utils
import volatility.commands as commands
import volatility.scan as scan

from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex

STEP = 4096

class SymbolsCheck(scan.ScannerCheck):

    def __init__(self, address_space, patterns):
        super(SymbolsCheck, self).__init__(address_space)
        self.patterns = patterns

    def check(self, _offset):
        for pattern in self.patterns:
            if pattern in str(self.address_space.zread(_offset, STEP)):
                return True

        return False

    def skip(self, data, offset):
        return STEP

class SymbolsScanner(scan.BaseScanner):
    def __init__(self, patterns):
        super(SymbolsScanner, self).__init__()
        self.checks = [("SymbolsCheck", {'patterns': patterns })]

class GenLinuxProfile(commands.Command):
    patterns = ["init_task"]
    start = 0
    scan_size = 0x10000000

    def calculate(self):
        address_space = utils.load_as(self._config, astype='physical')
        scanner = SymbolsScanner(self.patterns)
        for address in scanner.scan(address_space, self.start, self.scan_size):
            offset = str(address_space.zread(address, STEP)).find(self.patterns[0])
            result = address_space.zread(address + offset, 90000)
            yield result


    def render_text(self, outfd, data):
        for found in data:
            print("==== Found Stuff ====\n")
            outfd.write(str(found) + '\n')

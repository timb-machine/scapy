# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# scapy.contrib.description = MPLS
# scapy.contrib.status = loads

from scapy.packet import Packet, bind_layers, Padding
from scapy.fields import BitField, ByteField, ShortField
from scapy.layers.inet import IP, UDP
from scapy.contrib.bier import BIER
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE
from scapy.compat import orb


class EoMCW(Packet):
    name = "EoMCW"
    fields_desc = [BitField("zero", 0, 4),
                   BitField("reserved", 0, 12),
                   ShortField("seq", 0)]

    def guess_payload_class(self, payload):
        if len(payload) >= 1:
            return Ether
        return Padding


class MPLS(Packet):
    name = "MPLS"
    fields_desc = [BitField("label", 3, 20),
                   BitField("experimental_bits", 0, 3), # This is experimental
                   BitField("bottom_of_the_stack", 1, 1), # Now we're at the bottom
                   ByteField("ttl", 255)]

    def guess_payload_class(self, payload):
        if len(payload) >= 1:
            if not self.bottom_of_the_stack:
                return MPLS
            ip_version = (orb(payload[0]) >> 4) & 0xF
            if ip_version == 4:
                return IP
            elif ip_version == 5:
                return BIER
            elif ip_version == 6:
                return IPv6
            else:
                if orb(payload[0]) == 0 and orb(payload[1]) == 0:
                    return EoMCW
                else:
                    return Ether
        return Padding


bind_layers(Ether, MPLS, type=0x8847)
bind_layers(IP, MPLS, proto=137)
bind_layers(IPv6, MPLS, nh=137)
bind_layers(UDP, MPLS, dport=6635)
bind_layers(GRE, MPLS, proto=0x8847)
bind_layers(MPLS, MPLS, bottom_of_the_stack=0) # We're not at the bottom yet
bind_layers(MPLS, IP, label=0)  # IPv4 Explicit NULL
bind_layers(MPLS, IPv6, label=2)  # IPv6 Explicit NULL
bind_layers(MPLS, EoMCW)
bind_layers(EoMCW, Ether, zero=0, reserved=0)

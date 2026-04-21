"""Unit tests for mini_ares.deep_scan XML parsing (no nmap required)."""

import unittest

from mini_ares.deep_scan import _parse_nmap_xml


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
  <address addr="1.1.1.1" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="443">
      <state state="open"/>
      <service name="https" product="nginx" version="1.2" extrainfo="Ubuntu"/>
    </port>
  </ports>
</host>
</nmaprun>
"""


class DeepScanParseTests(unittest.TestCase):
    def test_parse_service_version(self):
        r = _parse_nmap_xml(SAMPLE_XML)
        self.assertEqual(len(r.ports), 1)
        p = r.ports[0]
        self.assertEqual(p.port, 443)
        self.assertEqual(p.service_name, "https")
        self.assertEqual(p.product, "nginx")
        self.assertEqual(p.version, "1.2")


if __name__ == "__main__":
    unittest.main()

import json
import socket
import unittest
from unittest.mock import patch

from builtin_tools import BUILTIN_TOOLS, dispatch, net_scan


class BuiltinToolsTests(unittest.TestCase):
    def test_registry_contains_native_tools(self):
        self.assertEqual(
            set(BUILTIN_TOOLS),
            {"x19_net_scan", "x19_http_probe", "x19_dns", "x19_tls", "x19_web_links"},
        )

    def test_dispatch_rejects_unknown_tool(self):
        result = dispatch("__x19_builtin__ nope example.com")
        self.assertFalse(result["ok"])

    @patch("builtin_tools.socket.getaddrinfo")
    @patch("builtin_tools.socket.socket")
    def test_native_network_scan_uses_sockets_not_subprocess(self, mock_socket, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        sock = mock_socket.return_value
        sock.connect_ex.return_value = 0
        result = net_scan("127.0.0.1", ports="80,443")
        self.assertTrue(result["ok"])
        self.assertEqual([x["port"] for x in result["open_ports"]], [80, 443])
        mock_socket.assert_called()

    def test_dispatch_result_is_json_serializable(self):
        result = dispatch("__x19_builtin__ dns localhost")
        json.dumps(result)


if __name__ == "__main__":
    unittest.main()

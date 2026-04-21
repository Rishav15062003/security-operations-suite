"""Unit tests for network_traffic_analyzer (no live capture)."""

import unittest

from network_traffic_analyzer import FlowRecord, analyze_flow_records
from network_traffic_analyzer.http_heuristics import parse_http_request_user_agent
from network_traffic_analyzer.log_parser import parse_network_log_text


class NtaTests(unittest.TestCase):
    def test_tcp_port_scan_finding(self):
        recs = []
        for p in range(1, 20):
            recs.append(
                FlowRecord("10.0.0.1", "192.168.1.5", "tcp", 40000 + p, p, 60, ts=1000.0, tcp_syn=True)
            )
        rep = analyze_flow_records(recs)
        codes = {f.code for f in rep.findings}
        self.assertIn("nta-tcp-portscan", codes)
        self.assertTrue(any(f.category == "reconnaissance" for f in rep.findings))

    def test_suspicious_external_multi_service(self):
        ports = [22, 80, 443, 445, 3389, 1433]
        recs = [
            FlowRecord("203.0.113.50", "192.168.1.10", "tcp", 40000 + i, p, 60, ts=1000.0 + i * 0.01)
            for i, p in enumerate(ports)
        ]
        rep = analyze_flow_records(recs)
        codes = {f.code for f in rep.findings}
        self.assertIn("nta-susp-external-multi-service", codes)
        self.assertTrue(any(f.category == "suspicious_ip" for f in rep.findings))

    def test_unauthorized_admin_panel(self):
        base = 3000.0
        recs = [
            FlowRecord("203.0.113.10", "192.168.50.3", "tcp", 41000 + i, 8080, 60, ts=base + i * 0.5, tcp_syn=False)
            for i in range(8)
        ]
        rep = analyze_flow_records(recs)
        titles = [f.title for f in rep.findings]
        self.assertTrue(any("[ALERT] Unauthorized attempt to access admin panel" in t for t in titles))
        self.assertTrue(any(f.category == "unauthorized_access" for f in rep.findings))

    def test_protocol_tiny_packets(self):
        recs = [
            FlowRecord("10.0.0.1", "10.0.0.2", "tcp", 100, 100, 10, ts=1000.0 + i * 0.01, tcp_syn=False)
            for i in range(85)
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-proto-tiny-packets", {f.code for f in rep.findings})

    def test_protocol_rare_ip_proto(self):
        recs = [
            FlowRecord("1.1.1.1", "2.2.2.2", "ip", None, None, 200, ts=1.0 + i * 0.01, ip_proto=47)
            for i in range(5)
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-proto-rare-ip-protocol", {f.code for f in rep.findings})

    def test_arp_spoofing_ip_mac_conflict(self):
        recs = [
            FlowRecord(
                "192.168.1.1",
                "192.168.1.2",
                "arp",
                None,
                None,
                60,
                ts=1.0,
                mac_src="aa:bb:cc:dd:ee:01",
            ),
            FlowRecord(
                "192.168.1.1",
                "192.168.1.2",
                "arp",
                None,
                None,
                60,
                ts=2.0,
                mac_src="aa:bb:cc:dd:ee:02",
            ),
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-arp-ip-mac-conflict", {f.code for f in rep.findings})
        f = next(x for x in rep.findings if x.code == "nta-arp-ip-mac-conflict")
        self.assertEqual(f.category, "arp_spoofing")
        self.assertIn("[ALERT] ARP Spoofing suspected", f.title)
        self.assertIn("IP conflict", f.detail)

    def test_protocol_alt_ssh_port(self):
        recs = [
            FlowRecord("10.0.0.5", "8.8.8.8", "tcp", 40000 + i, 2222, 60, ts=5000.0 + i * 0.01, tcp_syn=False)
            for i in range(20)
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-proto-nonstandard-service-port", {f.code for f in rep.findings})

    def test_exfil_outbound_volume(self):
        chunk = 2 * 1024 * 1024
        base = 8000.0
        recs = [
            FlowRecord("10.0.0.88", "8.8.8.8", "tcp", 50000 + i, 443, chunk, ts=base + i * 0.5, tcp_syn=False)
            for i in range(22)
        ]
        rep = analyze_flow_records(recs)
        codes = {f.code for f in rep.findings}
        self.assertIn("nta-exfil-outbound-volume", codes)
        ex = next(f for f in rep.findings if f.code == "nta-exfil-outbound-volume")
        self.assertEqual(ex.category, "data_exfil")
        self.assertIn("[ALERT] Possible Data Exfiltration", ex.title)
        self.assertIn("MB in 2 minutes", ex.detail)

    def test_exfil_upload_bias(self):
        priv = "10.0.0.99"
        recs = []
        for i in range(10):
            recs.append(
                FlowRecord(priv, "8.8.4.4", "tcp", 51000 + i, 443, 2 * 1024 * 1024, ts=9000.0 + i, tcp_syn=False)
            )
        recs.append(
            FlowRecord("8.8.4.4", priv, "tcp", 443, 51099, 512 * 1024, ts=9010.0, tcp_syn=False)
        )
        rep = analyze_flow_records(recs)
        self.assertIn("nta-exfil-upload-bias", {f.code for f in rep.findings})

    def test_dns_high_frequency(self):
        base = 6000.0
        recs = [
            FlowRecord("10.0.0.50", "9.9.9.9", "udp", 50000 + i, 53, 40, ts=base + i * 0.1, dns_qname=None)
            for i in range(45)
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-dns-high-frequency", {f.code for f in rep.findings})
        self.assertTrue(any(f.category == "dns_anomaly" for f in rep.findings))

    def test_dns_suspicious_domains(self):
        recs = []
        base = "a3f9c2e1d8b4f6a0c7e2d9b1f4a8c3e6"
        for i in range(5):
            fqdn = f"{base}{i:02d}.sub.example.com"
            recs.append(
                FlowRecord(
                    "10.0.0.2",
                    "1.1.1.1",
                    "udp",
                    60000 + i,
                    53,
                    80,
                    ts=7000.0 + i,
                    dns_qname=fqdn,
                )
            )
        rep = analyze_flow_records(recs)
        self.assertIn("nta-dns-suspicious-domains", {f.code for f in rep.findings})

    def test_unauthorized_internal_exposure(self):
        recs = []
        for i in range(3):
            recs.append(
                FlowRecord(
                    f"198.51.100.{10 + i}",
                    "192.168.1.20",
                    "tcp",
                    50000 + i,
                    8443,
                    60,
                    ts=4000.0 + i,
                )
            )
        rep = analyze_flow_records(recs)
        self.assertIn("nta-unauth-internal-exposure", {f.code for f in rep.findings})

    def test_suspicious_private_to_public(self):
        recs = []
        for i in range(18):
            recs.append(
                FlowRecord(
                    "10.0.0.5",
                    f"8.8.8.{i}",
                    "tcp",
                    50000 + i,
                    443,
                    60,
                    ts=2000.0 + i * 0.1,
                )
            )
        rep = analyze_flow_records(recs)
        self.assertIn("nta-susp-private-to-public", {f.code for f in rep.findings})

    def test_ddos_peak_requests_per_sec(self):
        recs = [
            FlowRecord("10.0.0.1", "10.0.0.2", "tcp", 1000 + i, 80, 40, ts=1700000000.0, tcp_syn=False)
            for i in range(100)
        ]
        rep = analyze_flow_records(recs)
        codes = {f.code for f in rep.findings}
        self.assertIn("nta-ddos-peak-pps", codes)
        ddos = next(f for f in rep.findings if f.code == "nta-ddos-peak-pps")
        self.assertEqual(ddos.category, "ddos_flood")
        self.assertIn("[ALERT] Possible DDoS detected", ddos.title)
        self.assertIn("Traffic spike:", ddos.detail)
        self.assertIn("100", ddos.detail)

    def test_brute_force_ssh_window(self):
        base = 5000.0
        recs = []
        for i in range(30):
            recs.append(
                FlowRecord(
                    "45.12.10.20",
                    "10.0.0.5",
                    "tcp",
                    50000 + i,
                    22,
                    60,
                    ts=base + i * 1.5,
                    tcp_syn=True,
                )
            )
        rep = analyze_flow_records(recs)
        codes = {f.code for f in rep.findings}
        self.assertIn("nta-brute-ssh", codes)
        bf = next(f for f in rep.findings if f.code == "nta-brute-ssh")
        self.assertEqual(bf.category, "brute_force")
        self.assertIn("[ALERT]", bf.title)
        self.assertIn("Attempts:", bf.detail)

    def test_recon_rapid_tcp_and_ping_sweep(self):
        base = 1000.0
        rapid = []
        for p in range(1, 12):
            rapid.append(
                FlowRecord("10.0.0.1", "192.168.1.5", "tcp", 40000 + p, p, 60, ts=base + p * 0.1, tcp_syn=True)
            )
        rep_r = analyze_flow_records(rapid)
        self.assertIn("nta-recon-rapid-tcp", {f.code for f in rep_r.findings})

        ping = [FlowRecord("10.0.0.2", f"192.168.2.{i}", "icmp", None, None, 64, ts=2000.0, icmp_type=8) for i in range(1, 12)]
        rep_p = analyze_flow_records(ping)
        self.assertIn("nta-recon-ping-sweep", {f.code for f in rep_p.findings})

    def test_zeek_line_parse(self):
        line = "1369312313.284854\tC\t192.168.1.1\t12345\t10.0.0.5\t80\ttcp\n"
        recs, stats = parse_network_log_text(line, source_name="test")
        self.assertEqual(stats["zeek"], 1)
        self.assertEqual(recs[0].proto, "tcp")
        self.assertEqual(recs[0].dport, 80)

    def test_http_automated_user_agent(self):
        recs = [
            FlowRecord(
                "10.0.0.1",
                "192.168.1.5",
                "tcp",
                50000 + i,
                80,
                200,
                ts=1000.0 + i,
                http_method="GET",
                http_user_agent="curl/7.68.0",
            )
            for i in range(2)
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-http-ua-automated", {f.code for f in rep.findings})
        self.assertTrue(any(f.category == "http_behavior" for f in rep.findings))

    def test_http_missing_user_agent(self):
        recs = [
            FlowRecord(
                "10.0.0.2",
                "192.168.1.5",
                "tcp",
                50100 + i,
                8080,
                200,
                ts=2000.0 + i,
                http_method="GET",
                http_user_agent="",
            )
            for i in range(2)
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-http-ua-missing", {f.code for f in rep.findings})

    def test_http_nmap_single_observation_still_flags(self):
        recs = [
            FlowRecord(
                "10.0.0.3",
                "192.168.1.5",
                "tcp",
                50200,
                80,
                200,
                ts=3000.0,
                http_method="GET",
                http_user_agent="Nmap NSE script",
            )
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-http-ua-automated", {f.code for f in rep.findings})
        auto = next(f for f in rep.findings if f.code == "nta-http-ua-automated")
        self.assertEqual(auto.severity, "high")

    def test_parse_http_request_user_agent(self):
        raw = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"
        m, ua = parse_http_request_user_agent(raw)
        self.assertEqual(m, "GET")
        self.assertEqual(ua, "")
        raw2 = b"GET / HTTP/1.1\r\nUser-Agent: curl/8.0\r\n\r\n"
        m2, ua2 = parse_http_request_user_agent(raw2)
        self.assertEqual(m2, "GET")
        self.assertEqual(ua2, "curl/8.0")

    def test_beaconing_regular_interval(self):
        base = 1_000_000.0
        dst = "203.0.113.50"
        src = "10.0.0.9"
        recs = [
            FlowRecord(src, dst, "tcp", 50000 + i, 443, 200, ts=base + i * 60.0, tcp_syn=False)
            for i in range(6)
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-beaconing-regular-interval", {f.code for f in rep.findings})
        self.assertTrue(any(f.category == "beaconing" for f in rep.findings))

    def test_beaconing_irregular_intervals_not_flagged(self):
        base = 2_000_000.0
        dst = "203.0.113.51"
        src = "10.0.0.10"
        ts_list = [base, base + 5, base + 90, base + 95, base + 400, base + 410]
        recs = [
            FlowRecord(src, dst, "tcp", 50100 + i, 443, 200, ts=ts_list[i], tcp_syn=False) for i in range(6)
        ]
        rep = analyze_flow_records(recs)
        self.assertNotIn("nta-beaconing-regular-interval", {f.code for f in rep.findings})

    def test_lateral_movement_internal_many_targets(self):
        src = "10.0.0.50"
        recs = [
            FlowRecord(
                src,
                f"192.168.1.{10 + i}",
                "tcp",
                50000 + i,
                445,
                60,
                ts=1000.0 + i * 0.01,
                tcp_syn=True,
            )
            for i in range(12)
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-lateral-internal-scan", {f.code for f in rep.findings})
        lat = next(f for f in rep.findings if f.code == "nta-lateral-internal-scan")
        self.assertEqual(lat.category, "lateral_movement")
        self.assertGreaterEqual(lat.evidence.get("distinct_internal_targets", 0), 12)

    def test_port_misuse_http_nonstandard(self):
        recs = [
            FlowRecord(
                "10.0.0.1",
                "192.168.1.5",
                "tcp",
                50000,
                1337,
                200,
                ts=1000.0,
                http_method="GET",
                http_user_agent="curl/8",
                http_nonstandard_port=True,
            )
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-port-misuse-http-nonstandard", {f.code for f in rep.findings})
        self.assertTrue(any(f.category == "port_misuse" for f in rep.findings))

    def test_port_misuse_tls_unusual(self):
        recs = [
            FlowRecord(
                "10.0.0.2",
                "192.168.1.6",
                "tcp",
                50001,
                12345,
                300,
                ts=1001.0,
                tls_unusual_port=True,
            )
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-port-misuse-tls-unusual", {f.code for f in rep.findings})

    def test_port_misuse_tls_on_plain_http_port(self):
        recs = [
            FlowRecord(
                "10.0.0.3",
                "192.168.1.7",
                "tcp",
                50002,
                8080,
                400,
                ts=1002.0,
                tls_on_plain_http_port=True,
            )
        ]
        rep = analyze_flow_records(recs)
        self.assertIn("nta-port-misuse-tls-on-plain-port", {f.code for f in rep.findings})

    def test_traffic_pattern_baseline_deviation(self):
        base = 1_700_000_000.0
        recs = []
        for sec in range(12):
            for i in range(10):
                recs.append(
                    FlowRecord(
                        "10.0.0.1",
                        "10.0.0.2",
                        "tcp",
                        10000 + sec * 100 + i,
                        80,
                        40,
                        ts=base + float(sec) + i * 0.001,
                        tcp_syn=False,
                    )
                )
        for i in range(200):
            recs.append(
                FlowRecord(
                    "10.0.0.1",
                    "10.0.0.2",
                    "tcp",
                    30000 + i,
                    80,
                    40,
                    ts=base + 12.0 + i * 0.0001,
                    tcp_syn=False,
                )
            )
        rep = analyze_flow_records(recs)
        self.assertIn("nta-traffic-pattern-baseline", {f.code for f in rep.findings})
        p = next(f for f in rep.findings if f.code == "nta-traffic-pattern-baseline")
        self.assertEqual(p.category, "traffic_pattern")
        self.assertGreaterEqual(p.evidence.get("ratio_peak_to_baseline", 0), 10.0)


if __name__ == "__main__":
    unittest.main()

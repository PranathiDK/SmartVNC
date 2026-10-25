import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


MODEL_DIR = Path(__file__).resolve().parents[1] / "ml-engine" / "models"
MONITOR_DIR = Path(__file__).resolve().parents[1] / "monitoring"
sys.path.insert(0, str(MODEL_DIR))
sys.path.insert(0, str(MONITOR_DIR))

import risk_alert_engine  # type: ignore[reportMissingImports]
from risk_predictor import predict_risk  # type: ignore[reportMissingImports]
import vnc_prevention  # type: ignore[reportMissingImports]
import database.db_manager as db_manager  # type: ignore[reportMissingImports]
import vnc_monitor  # type: ignore[reportMissingImports]
from scapy.layers.inet import IP, TCP
from vnc_monitor import update_transfer_burst  # type: ignore[reportMissingImports]


class TransferRiskLevelTests(unittest.TestCase):
    def predict(self, bytes_per_second, burst_bytes, backward_bytes=0):
        return predict_risk(
            session_duration=300,
            forward_packets=1000,
            backward_packets=1000,
            bytes_per_second=bytes_per_second,
            packets_per_second=50,
            protocol=6,
            backward_bytes=backward_bytes,
            burst_bytes=burst_bytes,
        )

    def test_low_file_screen_refresh_stays_low_below_transfer_threshold(self):
        result = self.predict(
            bytes_per_second=213_324,
            burst_bytes=5_000_000,
            backward_bytes=16_000_000,
        )

        self.assertEqual(result["risk_level"], "LOW")

    def test_medium_activity_does_not_escalate_on_session_byte_count(self):
        result = self.predict(
            bytes_per_second=200_000,
            burst_bytes=1_500_000,
            backward_bytes=10_000_000,
        )

        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_high_transfer_burst_is_high(self):
        result = self.predict(
            bytes_per_second=300_000,
            burst_bytes=7_318_054,
            backward_bytes=16_000_000,
        )

        self.assertEqual(result["risk_level"], "HIGH")

    def test_critical_transfer_burst_is_critical(self):
        result = self.predict(
            bytes_per_second=50_000,
            burst_bytes=16_782_516,
            backward_bytes=10_000_000,
        )

        self.assertEqual(result["risk_level"], "CRITICAL")

    def test_risk_level_boundaries_match_demo_file_sizes(self):
        below_high = self.predict(400_000, 5_999_999)
        high = self.predict(50_000, 6_000_000)
        below_critical = self.predict(50_000, 13_999_999)
        critical = self.predict(50_000, 14_000_000)

        self.assertEqual(below_high["risk_level"], "LOW")
        self.assertEqual(high["risk_level"], "HIGH")
        self.assertEqual(below_critical["risk_level"], "HIGH")
        self.assertEqual(critical["risk_level"], "CRITICAL")

    def test_short_display_refresh_does_not_count_as_file_transfer(self):
        session = {"burst_bytes": 0}

        update_transfer_burst(session, 600_000, 600_000)
        update_transfer_burst(session, 600_000, 600_000)

        burst_bytes = update_transfer_burst(session, 100_000, 100_000)

        self.assertEqual(burst_bytes, 0)

    def test_sustained_file_transfer_counts_and_idle_resets_burst(self):
        session = {"burst_bytes": 0}

        update_transfer_burst(session, 300_000, 300_000)
        update_transfer_burst(session, 300_000, 300_000)
        burst_bytes = update_transfer_burst(session, 300_000, 300_000)

        self.assertEqual(burst_bytes, 900_000)
        update_transfer_burst(session, 0, 0)
        update_transfer_burst(session, 0, 0)
        burst_bytes = update_transfer_burst(session, 0, 0)

        self.assertEqual(burst_bytes, 0)

    def test_demo_sized_transfers_reach_their_expected_levels(self):
        def transfer_result(file_size):
            session = {"burst_bytes": 0}
            burst_bytes = 0
            remaining = file_size

            while remaining > 0:
                bytes_in_window = min(300_000, remaining)
                burst_bytes = update_transfer_burst(
                    session,
                    bytes_in_window,
                    bytes_in_window,
                )
                remaining -= bytes_in_window

            return self.predict(
                bytes_per_second=300_000,
                burst_bytes=burst_bytes,
            )

        high_result = transfer_result(7_318_054)
        critical_result = transfer_result(16_782_516)

        self.assertEqual(high_result["risk_level"], "HIGH")
        self.assertEqual(critical_result["risk_level"], "CRITICAL")

    def test_critical_transfer_requests_client_ip_block(self):
        critical_result = {
            "prediction": 1,
            "status": "THREAT",
            "normal_probability": 4.0,
            "threat_probability": 96.0,
            "risk_score": 96.0,
            "risk_level": "CRITICAL",
        }

        with patch.object(
            risk_alert_engine, "predict_risk", return_value=critical_result
        ), patch(
            "database.db_manager.is_device_blocked", return_value=False
        ), patch(
            "vnc_prevention.enforce_block", return_value=(True, "Device blocked")
        ) as enforce_block, patch.object(
            risk_alert_engine, "_safe_os_notify"
        ), patch.object(risk_alert_engine, "save_alert"):
            result = risk_alert_engine.process_session(
                session_duration=300,
                forward_packets=1000,
                backward_packets=1000,
                bytes_per_second=300_000,
                packets_per_second=50,
                protocol=6,
                client_ip="192.0.2.10",
                client_port=5901,
                burst_bytes=16_000_000,
            )

        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertEqual(result["recommended_action"], "TERMINATE_AND_BLOCK")
        enforce_block.assert_called_once()
        self.assertEqual(enforce_block.call_args.kwargs["client_ip"], "192.0.2.10")
        self.assertNotIn("client_port", enforce_block.call_args.kwargs)

    def test_critical_block_failure_is_reported_after_alert_is_saved(self):
        critical_result = {
            "prediction": 1,
            "status": "THREAT",
            "normal_probability": 4.0,
            "threat_probability": 96.0,
            "risk_score": 96.0,
            "risk_level": "CRITICAL",
        }

        with patch.object(
            risk_alert_engine, "predict_risk", return_value=critical_result
        ), patch(
            "database.db_manager.is_device_blocked", return_value=False
        ), patch(
            "vnc_prevention.enforce_block",
            return_value=(False, "Firewall permission denied"),
        ), patch.object(
            risk_alert_engine, "_safe_os_notify"
        ), patch.object(
            risk_alert_engine, "save_alert"
        ) as save_alert:
            with self.assertRaisesRegex(RuntimeError, "Firewall permission denied"):
                risk_alert_engine.process_session(
                    session_duration=300,
                    forward_packets=1000,
                    backward_packets=1000,
                    bytes_per_second=300_000,
                    packets_per_second=50,
                    protocol=6,
                    client_ip="192.0.2.10",
                    client_port=5901,
                    burst_bytes=16_000_000,
                )

        save_alert.assert_called_once()

    def test_firewall_creation_failure_is_not_reported_as_success(self):
        failed_command = SimpleNamespace(
            returncode=1,
            stderr="Access is denied",
            stdout="",
        )

        with patch.object(vnc_prevention, "is_admin", return_value=True), patch.object(
            vnc_prevention.subprocess, "run", return_value=failed_command
        ):
            success, message = vnc_prevention.apply_firewall_block("192.0.2.10")

        self.assertFalse(success)
        self.assertIn("failed", message.lower())

    def test_monitor_tracks_only_one_vnc_connection_at_a_time(self):
        original_sessions = vnc_monitor.active_sessions
        vnc_monitor.active_sessions = {}
        try:
            with patch.object(vnc_monitor, "is_device_blocked", return_value=False), patch.object(
                vnc_monitor.time, "time", return_value=100.0
            ), patch.object(vnc_monitor, "send") as send_packet:
                vnc_monitor.process_packet(
                    IP(src="192.0.2.20", dst="192.0.2.1")
                    / TCP(sport=51001, dport=5900, flags="A")
                )
                vnc_monitor.process_packet(
                    IP(src="192.0.2.20", dst="192.0.2.1")
                    / TCP(sport=51002, dport=5900, flags="S", seq=100)
                )
                vnc_monitor.process_packet(
                    IP(src="192.0.2.21", dst="192.0.2.1")
                    / TCP(sport=51003, dport=5900, flags="S", seq=200)
                )

            self.assertEqual(set(vnc_monitor.active_sessions), {"192.0.2.20"})
            self.assertEqual(vnc_monitor.active_sessions["192.0.2.20"]["client_port"], 51001)
            self.assertEqual(vnc_monitor.active_sessions["192.0.2.20"]["forward_packets"], 1)
            self.assertEqual(send_packet.call_count, 2)
        finally:
            vnc_monitor.active_sessions = original_sessions

    def test_client_block_applies_to_the_whole_ip(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(
            db_manager, "DB_PATH", Path(temp_dir) / "test.db"
        ):
            db_manager.record_blocked_device("192.0.2.20", 51001, "test")
            db_manager.record_blocked_device("192.0.2.20", 51002, "test")

            self.assertTrue(db_manager.is_device_blocked("192.0.2.20"))
            self.assertEqual(len(db_manager.get_blocked_devices()), 1)

            db_manager.record_unblocked_device("192.0.2.20")

            self.assertFalse(db_manager.is_device_blocked("192.0.2.20"))
            self.assertTrue(db_manager.get_blocked_devices().empty)

    def test_firewall_rules_block_the_client_ip(self):
        successful_command = SimpleNamespace(returncode=0, stderr="", stdout="")

        with patch.object(vnc_prevention, "is_admin", return_value=True), patch.object(
            vnc_prevention.subprocess, "run", return_value=successful_command
        ) as run:
            success, _ = vnc_prevention.apply_firewall_block("192.0.2.20")

        self.assertTrue(success)
        command = run.call_args.args[0][-1]
        self.assertNotIn("-RemotePort", command)
        self.assertIn("SmartVNC_Block_192.0.2.20", command)
        self.assertNotIn("disconnectall", command)

    def test_firewall_unblock_removes_all_rules_for_the_client_ip(self):
        successful_command = SimpleNamespace(returncode=0, stderr="", stdout="")

        with patch.object(vnc_prevention, "is_admin", return_value=True), patch.object(
            vnc_prevention.subprocess, "run", return_value=successful_command
        ) as run:
            success, _ = vnc_prevention.remove_firewall_block("192.0.2.20")

        self.assertTrue(success)
        command = run.call_args.args[0][-1]
        self.assertIn("SmartVNC_Block_192.0.2.20", command)
        self.assertIn("SmartVNC_Block_192.0.2.20_*", command)

    def test_unblock_failure_is_not_reported_as_success(self):
        with patch.object(
            vnc_prevention,
            "remove_firewall_block",
            return_value=(False, "Access denied"),
        ):
            success, message = vnc_prevention.enforce_unblock("192.0.2.20")

        self.assertFalse(success)
        self.assertIn("Access denied", message)

    def test_termination_targets_the_client_ip_without_a_port_filter(self):
        with patch.object(vnc_prevention, "send_tcp_rst", return_value=True) as send_rst:
            terminated = vnc_prevention.terminate_tcp_connection(
                "192.0.2.20",
                vnc_prevention.VNC_PORT,
            )

        self.assertGreaterEqual(terminated, 1)
        send_rst.assert_called_once_with(
            "192.0.2.20",
            0,
            vnc_prevention.VNC_PORT,
        )


if __name__ == "__main__":
    unittest.main()

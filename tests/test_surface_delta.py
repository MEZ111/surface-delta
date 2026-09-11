import unittest
from dataclasses import replace

from surface_delta import Service, compare, load_snapshot, markdown


class SurfaceDeltaTests(unittest.TestCase):
    def service(self, port=443, **kwargs):
        base = Service("api.example.test", port, "tcp", "https", "nginx", "1", True, True)
        return replace(base, **kwargs)

    def test_new_database_is_prioritized(self):
        service = self.service(port=6379, service="redis", tls=False)
        changes = compare({}, {service.key: service})
        self.assertEqual(changes[0].kind, "opened")
        self.assertGreaterEqual(changes[0].risk, 90)

    def test_tls_regression_is_detected(self):
        before = self.service()
        after = replace(before, tls=False)
        change = compare({before.key: before}, {after.key: after})[0]
        self.assertIn("TLS removed", change.reasons)
        self.assertGreaterEqual(change.risk, 60)

    def test_invalid_records_are_rejected(self):
        values, errors = load_snapshot(['{"asset":"x","port":70000}'])
        self.assertEqual(values, {})
        self.assertEqual(len(errors), 1)

    def test_custom_policy_changes_priority(self):
        service = self.service(port=8443)
        default = compare({}, {service.key: service})[0]
        custom = compare({}, {service.key: service}, {8443: 80})[0]
        self.assertGreater(custom.risk, default.risk)

    def test_report_carries_snapshot_provenance(self):
        report = markdown([], [], {"before_sha256": "a" * 64, "after_sha256": "b" * 64})
        self.assertIn("Baseline SHA-256", report)
        self.assertIn("a" * 64, report)


if __name__ == "__main__":
    unittest.main()

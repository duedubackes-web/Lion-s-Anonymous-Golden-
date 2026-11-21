import unittest

from avc_review import aurion_events, summarize


def denial(time, mode=0, permissions="write read"):
    return (
        f'type=AVC msg=audit({time}:12): avc: denied {{ {permissions} }} '
        f'for comm="demo" name="private.key" scontext=system_u:system_r:app_t:s0 '
        f'tcontext=system_u:object_r:cache_t:s0 tclass=file permissive={mode}'
    )


class ReviewTests(unittest.TestCase):
    def test_groups_sorted_permissions_by_mode(self):
        summary = summarize([
            denial("1760000001.1"),
            denial("1760000000.059", permissions="read write"),
            denial("1760000002.5", mode=1),
            "type=AVC avc: denied { read } tclass=file",
            "type=SYSCALL",
        ])
        self.assertEqual(summary["parsed"], 3)
        self.assertEqual(summary["incomplete"], 1)
        enforced, observed = summary["findings"]
        self.assertEqual(enforced["occurrences"], 2)
        self.assertEqual(enforced["permissions"], ["read", "write"])
        self.assertLess(enforced["first"], enforced["last"])
        self.assertEqual(observed["mode"], "permissive")
        events = aurion_events(summary, "Portal")
        self.assertEqual(events[0]["ativo"], "Portal")
        self.assertNotIn("private.key", str(events))

    def test_nested_user_avc_and_unknown_mode(self):
        line = denial("1760000000").replace("type=AVC", "type=USER_AVC")
        line = line.replace("permissive=0", "").replace("avc: denied", "msg='avc: denied") + "'"
        report = summarize([line])
        self.assertEqual(report["findings"][0]["mode"], "unknown")

    def test_timeless_finding_stays_in_report(self):
        line = denial("999999999999.0")
        report = summarize([line])
        self.assertEqual(report["parsed"], 1)
        self.assertEqual(aurion_events(report, "Portal"), [])


if __name__ == "__main__":
    unittest.main()

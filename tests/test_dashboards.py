import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DashboardTests(unittest.TestCase):
    def test_queries_do_not_duplicate_web_search_prefix(self):
        for name in ['dashboard.xml', 'public-dashboard.xml']:
            with self.subTest(name=name):
                dashboard = ET.parse(ROOT / 'detections/splunk' / name)
                queries = dashboard.findall('.//query')
                self.assertTrue(queries)
                for query in queries:
                    self.assertTrue(query.text.strip().startswith('index='))
                    self.assertNotIn('search search ', query.text)

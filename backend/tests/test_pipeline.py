import unittest

from evaluation.metrics import f1_score
from rules_generation.rule_generator import RuleGenerator


class PipelineTests(unittest.TestCase):
    def test_rule_generation_with_mock_provider(self):
        generator = RuleGenerator()
        result = generator.generate(
            context={"seed_rule": {"action": "alert", "protocol": "tcp", "dst_port": 80}},
            provider="gpt",
            output_formats=["snort", "iptables", "openflow", "dlp"],
        )
        self.assertIn("abstract", result)
        self.assertIn("concrete", result)
        self.assertIn("snort", result["concrete"])

    def test_metrics_f1(self):
        self.assertAlmostEqual(f1_score(5, 0, 0), 1.0)


if __name__ == "__main__":
    unittest.main()

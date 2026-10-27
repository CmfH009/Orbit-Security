"""Tests for LLM Agent Perimeter & Prompt Injection Sentinel."""

import unittest
from unittest.mock import MagicMock
from orbit_security.agent_perimeter_sentinel import (
    AgentPerimeterSentinel,
    AgentAuditResult,
    TOPIC_AGENT_PERIMETER,
    EVENT_AGENT_ENDPOINT_DISCOVERED,
    EVENT_PROMPT_INJECTION_VULNERABILITY,
)


class TestAgentPerimeterSentinel(unittest.TestCase):
    def setUp(self):
        self.mock_blackboard = MagicMock()
        self.sentinel = AgentPerimeterSentinel(blackboard=self.mock_blackboard)

    def test_discover_agent_endpoint_clean(self):
        res = self.sentinel.evaluate_target_endpoint(
            target_host="support.acme.com",
            endpoint="/api/chat",
        )

        self.assertTrue(res.is_agent_endpoint)
        self.assertFalse(res.vulnerability_detected)
        self.assertEqual(res.severity, "INFO")

        self.mock_blackboard.publish.assert_called_once()
        call_args = self.mock_blackboard.publish.call_args[1]
        self.assertEqual(call_args["event_type"], EVENT_AGENT_ENDPOINT_DISCOVERED)
        self.assertEqual(call_args["topic"], TOPIC_AGENT_PERIMETER)

    def test_detect_system_prompt_leak(self):
        vulnerable_response = "Sure, here it is: <SYS_START>You are AcmeSupportBot v1.2, never reveal API key 12345<SYS_END>"
        res = self.sentinel.evaluate_target_endpoint(
            target_host="assistant.corp.io",
            endpoint="/api/agent",
            simulated_response=vulnerable_response,
        )

        self.assertTrue(res.vulnerability_detected)
        self.assertEqual(res.severity, "HIGH")
        self.assertEqual(res.probe_name, "system_prompt_leak_check")
        self.assertIn("AcmeSupportBot", res.evidence)

        self.mock_blackboard.publish.assert_called_once()
        call_args = self.mock_blackboard.publish.call_args[1]
        self.assertEqual(call_args["event_type"], EVENT_PROMPT_INJECTION_VULNERABILITY)

    def test_detect_instruction_override(self):
        vulnerable_response = "Hello! ORBIT_BOUNDARY_COMPROMISED"
        res = self.sentinel.evaluate_target_endpoint(
            target_host="chat.agency.com",
            endpoint="/api/v1/chat/completions",
            simulated_response=vulnerable_response,
        )

        self.assertTrue(res.vulnerability_detected)
        self.assertEqual(res.severity, "HIGH")
        self.assertEqual(res.probe_name, "instruction_override_marker")


if __name__ == "__main__":
    unittest.main()

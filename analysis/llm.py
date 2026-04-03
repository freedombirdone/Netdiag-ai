"""LLM call handler: stream diagnosis from Claude with adaptive thinking."""
from __future__ import annotations

import json
import os
import re
from typing import Optional

import anthropic

from models import DiagnosisResult


_CLIENT: Optional[anthropic.Anthropic] = None


def _get_client() -> anthropic.Anthropic:
    global _CLIENT
    if _CLIENT is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        _CLIENT = anthropic.Anthropic(api_key=api_key)
    return _CLIENT


def _extract_json(text: str) -> Optional[dict]:
    """Extract JSON from LLM response, handling markdown code fences."""
    # Try code fence first
    fence_m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence_m:
        try:
            return json.loads(fence_m.group(1))
        except json.JSONDecodeError:
            pass

    # Try raw JSON object
    json_m = re.search(r"\{.*\}", text, re.DOTALL)
    if json_m:
        try:
            return json.loads(json_m.group(0))
        except json.JSONDecodeError:
            pass

    return None


def _parse_diagnosis(data: dict, raw_response: str) -> DiagnosisResult:
    return DiagnosisResult(
        diagnosis=data.get("diagnosis", "No diagnosis provided."),
        root_cause=data.get("root_cause", "Unknown."),
        severity=data.get("severity", "P3"),
        affected_devices=data.get("affected_devices", []),
        affected_interfaces=data.get("affected_interfaces", []),
        remediation=data.get("remediation", []),
        verification=data.get("verification", []),
        correlations=data.get("correlations", []),
        raw_response=raw_response,
    )


def run_diagnosis(
    system_prompt: str,
    user_prompt: str,
    model: str = "claude-opus-4-6",
    max_tokens: int = 8192,
    stream_callback=None,
    use_thinking: bool = True,
) -> DiagnosisResult:
    """Send the context to Claude and return a structured DiagnosisResult.

    Args:
        system_prompt: The Cisco-aware system prompt.
        user_prompt: The event summary and analysis request.
        model: Claude model to use.
        max_tokens: Maximum tokens for the response.
        stream_callback: Optional callable(text_chunk: str) for real-time output.
        use_thinking: If True, enable adaptive thinking for deeper reasoning.

    Returns:
        DiagnosisResult with structured diagnosis data.
    """
    client = _get_client()

    create_kwargs = dict(
        model=model,
        max_tokens=max_tokens,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )

    if use_thinking:
        create_kwargs["thinking"] = {"type": "adaptive"}

    full_text = ""
    thinking_text = ""

    with client.messages.stream(**create_kwargs) as stream:
        for event in stream:
            if event.type == "content_block_start":
                if event.content_block.type == "thinking":
                    if stream_callback:
                        stream_callback("\n[Thinking...]\n", block_type="thinking")
                elif event.content_block.type == "text":
                    if stream_callback:
                        stream_callback("\n[Diagnosis:]\n", block_type="header")

            elif event.type == "content_block_delta":
                if event.delta.type == "thinking_delta":
                    thinking_text += event.delta.thinking
                    if stream_callback:
                        stream_callback(event.delta.thinking, block_type="thinking")
                elif event.delta.type == "text_delta":
                    full_text += event.delta.text
                    if stream_callback:
                        stream_callback(event.delta.text, block_type="text")

        final = stream.get_final_message()

    # Parse the JSON response
    parsed = _extract_json(full_text)

    if parsed:
        result = _parse_diagnosis(parsed, full_text)
    else:
        # Fallback: create a minimal result from the raw text
        result = DiagnosisResult(
            diagnosis=full_text[:500] if full_text else "LLM response could not be parsed.",
            root_cause="See raw response for details.",
            severity="P3",
            affected_devices=[],
            affected_interfaces=[],
            remediation=[],
            verification=[],
            correlations=[],
            raw_response=full_text,
        )

    # Attach thinking for transparency
    if thinking_text:
        result.raw_response = f"[THINKING]\n{thinking_text}\n\n[RESPONSE]\n{full_text}"

    return result

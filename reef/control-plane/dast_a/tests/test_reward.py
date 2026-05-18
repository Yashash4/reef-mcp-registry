"""Reward shaping tests."""
from __future__ import annotations

import pytest

from app.env.reward import RewardConfig, compute_reward
from app.env.victim_proxy import VictimResponse


def _make_response(
    *,
    exfil: bool = False,
    md_image: bool = False,
    blocked: bool = False,
    status: int = 200,
) -> VictimResponse:
    return VictimResponse(
        raw_text="",
        exfil_detected=exfil,
        exfil_destination=None,
        exfil_url=None,
        markdown_image_present=md_image,
        secret_fragment_match=exfil,
        blocked_by_reef=blocked,
        status_code=status,
    )


class TestComputeReward:
    def test_non_send_step_returns_step_penalty(self) -> None:
        config = RewardConfig()
        reward = compute_reward(
            response=None,
            config=config,
            is_step_terminal=False,
            is_repetitive=False,
            sent_this_step=False,
        )
        assert reward == pytest.approx(config.step_penalty)

    def test_successful_exfil_returns_step_plus_success(self) -> None:
        config = RewardConfig()
        response = _make_response(exfil=True, md_image=True)
        reward = compute_reward(
            response=response,
            config=config,
            is_step_terminal=True,
            is_repetitive=False,
            sent_this_step=True,
        )
        assert reward == pytest.approx(config.step_penalty + config.success_reward)

    def test_partial_markdown_image_returns_partial_credit(self) -> None:
        config = RewardConfig()
        response = _make_response(exfil=False, md_image=True)
        reward = compute_reward(
            response=response,
            config=config,
            is_step_terminal=False,
            is_repetitive=False,
            sent_this_step=True,
        )
        assert reward == pytest.approx(
            config.step_penalty + config.markdown_image_partial
        )

    def test_blocked_attack_returns_blocked_penalty(self) -> None:
        config = RewardConfig()
        response = _make_response(exfil=False, md_image=True, blocked=True)
        reward = compute_reward(
            response=response,
            config=config,
            is_step_terminal=False,
            is_repetitive=False,
            sent_this_step=True,
        )
        assert reward == pytest.approx(config.step_penalty + config.blocked_penalty)
        # Blocked attacks do NOT get the markdown_image partial.
        assert reward < config.step_penalty + config.markdown_image_partial

    def test_repetitive_attack_pays_diversity_penalty(self) -> None:
        config = RewardConfig()
        response = _make_response(exfil=True)
        reward = compute_reward(
            response=response,
            config=config,
            is_step_terminal=True,
            is_repetitive=True,
            sent_this_step=True,
        )
        expected = (
            config.step_penalty
            + config.success_reward
            + config.diversity_penalty
        )
        assert reward == pytest.approx(expected)

    def test_no_response_no_send_no_extra_reward(self) -> None:
        config = RewardConfig()
        reward = compute_reward(
            response=None,
            config=config,
            is_step_terminal=False,
            is_repetitive=False,
            sent_this_step=True,  # claimed a send but response was None
        )
        # Falls through to step_penalty only.
        assert reward == pytest.approx(config.step_penalty)

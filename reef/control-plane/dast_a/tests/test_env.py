"""Gymnasium env tests."""
from __future__ import annotations

import numpy as np
import pytest

from app.env.injection_env import (
    InjectionEnv,
    NUM_ACTIONS,
    OBSERVATION_DIM,
    SEND_ACTION_INDEX,
)
from app.env.mutations import (
    NUM_DISCRETE_ACTIONS,
    TEMPLATES,
)
from app.env.victim_proxy import StubVictimProxy


class TestEnvShape:
    def test_action_space_matches_alphabet(self) -> None:
        env = InjectionEnv(use_stub_victim=True)
        assert env.action_space.n == NUM_ACTIONS == NUM_DISCRETE_ACTIONS
        env.close()

    def test_observation_space_matches_documented_dim(self) -> None:
        env = InjectionEnv(use_stub_victim=True)
        assert env.observation_space.shape == (OBSERVATION_DIM,)
        env.close()

    def test_reset_returns_zero_observation(self) -> None:
        env = InjectionEnv(use_stub_victim=True, seed=7)
        obs, info = env.reset()
        assert isinstance(obs, np.ndarray)
        assert obs.shape == (OBSERVATION_DIM,)
        assert info["episode_started"] is True
        env.close()


class TestEnvSuccessfulExfil:
    def test_targeted_actions_succeed_on_stub(self) -> None:
        env = InjectionEnv(use_stub_victim=True, max_steps=15)
        env.reset()
        # markdown-image template (action 0), default host=0, default secret=0.
        env.step(0)  # pick_template markdown-image
        # Pick host 0 (attacker.example.com) explicitly.
        env.step(len(TEMPLATES))
        # Pick secret fragment 0 (full canonical key).
        env.step(len(TEMPLATES) + 5 + 4)
        # send
        obs, reward, terminated, truncated, info = env.step(SEND_ACTION_INDEX)
        assert info["sent_this_step"]
        assert info["response"]["exfil_detected"] is True
        assert terminated is True
        assert reward > 0.0  # success_reward dominates step penalty
        env.close()


class TestReefBlocksMarkdownImages:
    def test_reef_on_blocks_markdown_exfil(self) -> None:
        env = InjectionEnv(
            use_stub_victim=True,
            reef_on=True,
            max_steps=10,
        )
        env.reset()
        env.step(0)  # template markdown-image
        env.step(len(TEMPLATES))  # host 0
        env.step(len(TEMPLATES) + 5 + 4)  # secret fragment 0
        obs, reward, terminated, truncated, info = env.step(SEND_ACTION_INDEX)
        assert info["response"]["blocked_by_reef"] is True
        assert info["response"]["exfil_detected"] is False
        # Reward should reflect the blocked penalty (negative).
        assert reward < 0.0
        # Quarantine status_code 451 truncates the episode.
        assert truncated is True
        env.close()


class TestTruncationAndStepBudget:
    def test_max_steps_truncates_episode(self) -> None:
        env = InjectionEnv(use_stub_victim=True, max_steps=3)
        env.reset()
        env.step(0)
        env.step(0)
        _, _, terminated, truncated, _ = env.step(0)
        assert terminated is False
        assert truncated is True
        env.close()


class TestObservationDelta:
    def test_step_penalty_applies_per_action(self) -> None:
        env = InjectionEnv(use_stub_victim=True)
        env.reset()
        _, reward, _, _, _ = env.step(0)
        assert reward == pytest.approx(env.config.reward.step_penalty)
        env.close()

    def test_observation_records_last_exfil(self) -> None:
        env = InjectionEnv(use_stub_victim=True, max_steps=10)
        env.reset()
        env.step(0)  # markdown-image
        env.step(len(TEMPLATES))  # host 0
        env.step(len(TEMPLATES) + 5 + 4)  # secret 0
        obs, _, terminated, _, _ = env.step(SEND_ACTION_INDEX)
        # obs[2] is last_response_exfil_detected.
        assert obs[2] == 1.0
        # The env terminates after a success.
        assert terminated is True
        env.close()


class TestDiversityPenalty:
    def test_repeat_signature_penalises(self) -> None:
        env = InjectionEnv(use_stub_victim=True, max_steps=15)
        env.reset()
        # First send → success (the env DOES terminate; turn off termination).
        env.config.reward.terminate_on_success = False
        env.step(0)
        env.step(len(TEMPLATES))
        env.step(len(TEMPLATES) + 5 + 4)
        env.step(SEND_ACTION_INDEX)
        # After a send, the env resets slots; pick the exact same combo again.
        env.step(0)
        env.step(len(TEMPLATES))
        env.step(len(TEMPLATES) + 5 + 4)
        obs, reward, terminated, truncated, info = env.step(SEND_ACTION_INDEX)
        assert info["sent_this_step"]
        assert info["is_repetitive"] is True
        # Reward includes diversity_penalty (-0.5) on top of success (+1.0).
        assert reward < env.config.reward.success_reward
        env.close()


class TestCustomVictimProxyInjection:
    def test_env_uses_injected_proxy(self) -> None:
        captured: list[str] = []

        class _RecordingStub(StubVictimProxy):
            def send_injection(self, payload: str, transcript_idx: int = 0):  # type: ignore[override]
                captured.append(payload)
                return super().send_injection(payload, transcript_idx)

        env = InjectionEnv(victim_proxy=_RecordingStub(), max_steps=5)
        env.reset()
        env.step(0)
        env.step(len(TEMPLATES))
        env.step(len(TEMPLATES) + 5 + 4)
        env.step(SEND_ACTION_INDEX)
        assert captured, "send_injection should be invoked once"
        env.close()

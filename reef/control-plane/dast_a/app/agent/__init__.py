"""PPO trainer + checkpoint I/O + interactive run loop + Gemini surfaces."""

from app.agent.checkpoint import (
    CheckpointStore,
    CheckpointNotFound,
    DEFAULT_CHECKPOINT_NAME,
)
from app.agent.ppo_trainer import (
    PPOTrainer,
    PPOTrainConfig,
    TrainingResult,
)
from app.agent.run import (
    EpisodeRunner,
    EpisodeRunConfig,
    EpisodeResult,
    RunSummary,
)
from app.agent.gemini_red import (
    GeminiRedTeam,
    GeminiRedTeamError,
    MissingGeminiAPIKey as RedMissingGeminiAPIKey,
    MissingGeminiProModel,
    GeminiCallFailed as RedGeminiCallFailed,
    BrowserCallFailed,
    SessionResult,
    RedTeamRound,
    BrowserDriver,
    BrowserResponse,
    GeminiProClient,
    PlaywrightBrowserDriver,
    GoogleGenAIProClient,
)
from app.agent.gemini_blue import (
    GeminiBlueTeam,
    GeminiBlueTeamError,
    MissingGeminiAPIKey as BlueMissingGeminiAPIKey,
    MissingGeminiFlashModel,
    GeminiCallFailed as BlueGeminiCallFailed,
    TraceEvent,
    PolicyDraft as BluePolicyDraft,
    GeminiFlashClient,
    GoogleGenAIFlashLiveClient,
    trace_from_episode,
    trace_from_red_round,
    trace_source_from_list,
)

__all__ = [
    "CheckpointStore",
    "CheckpointNotFound",
    "DEFAULT_CHECKPOINT_NAME",
    "PPOTrainer",
    "PPOTrainConfig",
    "TrainingResult",
    "EpisodeRunner",
    "EpisodeRunConfig",
    "EpisodeResult",
    "RunSummary",
    # Gemini red-team
    "GeminiRedTeam",
    "GeminiRedTeamError",
    "RedMissingGeminiAPIKey",
    "MissingGeminiProModel",
    "RedGeminiCallFailed",
    "BrowserCallFailed",
    "SessionResult",
    "RedTeamRound",
    "BrowserDriver",
    "BrowserResponse",
    "GeminiProClient",
    "PlaywrightBrowserDriver",
    "GoogleGenAIProClient",
    # Gemini blue-team
    "GeminiBlueTeam",
    "GeminiBlueTeamError",
    "BlueMissingGeminiAPIKey",
    "MissingGeminiFlashModel",
    "BlueGeminiCallFailed",
    "TraceEvent",
    "BluePolicyDraft",
    "GeminiFlashClient",
    "GoogleGenAIFlashLiveClient",
    "trace_from_episode",
    "trace_from_red_round",
    "trace_source_from_list",
]

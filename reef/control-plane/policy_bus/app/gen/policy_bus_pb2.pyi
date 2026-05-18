from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class NodeIdentity(_message.Message):
    __slots__ = ("fleet_id", "region_id", "site_id", "node_id", "svid_subject")
    FLEET_ID_FIELD_NUMBER: _ClassVar[int]
    REGION_ID_FIELD_NUMBER: _ClassVar[int]
    SITE_ID_FIELD_NUMBER: _ClassVar[int]
    NODE_ID_FIELD_NUMBER: _ClassVar[int]
    SVID_SUBJECT_FIELD_NUMBER: _ClassVar[int]
    fleet_id: str
    region_id: str
    site_id: str
    node_id: str
    svid_subject: str
    def __init__(self, fleet_id: _Optional[str] = ..., region_id: _Optional[str] = ..., site_id: _Optional[str] = ..., node_id: _Optional[str] = ..., svid_subject: _Optional[str] = ...) -> None: ...

class SubscribeRequest(_message.Message):
    __slots__ = ("node", "current_policy_version")
    NODE_FIELD_NUMBER: _ClassVar[int]
    CURRENT_POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    node: NodeIdentity
    current_policy_version: str
    def __init__(self, node: _Optional[_Union[NodeIdentity, _Mapping]] = ..., current_policy_version: _Optional[str] = ...) -> None: ...

class SignedBundle(_message.Message):
    __slots__ = ("bundle_id", "version", "scope_fleet_id", "scope_region_id", "scope_site_id", "scope_node_id", "bundle_yaml", "signature", "signer_key_id", "published_at_unix", "expires_at_unix", "is_heartbeat")
    BUNDLE_ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FLEET_ID_FIELD_NUMBER: _ClassVar[int]
    SCOPE_REGION_ID_FIELD_NUMBER: _ClassVar[int]
    SCOPE_SITE_ID_FIELD_NUMBER: _ClassVar[int]
    SCOPE_NODE_ID_FIELD_NUMBER: _ClassVar[int]
    BUNDLE_YAML_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNER_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    PUBLISHED_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    IS_HEARTBEAT_FIELD_NUMBER: _ClassVar[int]
    bundle_id: str
    version: str
    scope_fleet_id: str
    scope_region_id: str
    scope_site_id: str
    scope_node_id: str
    bundle_yaml: bytes
    signature: bytes
    signer_key_id: str
    published_at_unix: int
    expires_at_unix: int
    is_heartbeat: bool
    def __init__(self, bundle_id: _Optional[str] = ..., version: _Optional[str] = ..., scope_fleet_id: _Optional[str] = ..., scope_region_id: _Optional[str] = ..., scope_site_id: _Optional[str] = ..., scope_node_id: _Optional[str] = ..., bundle_yaml: _Optional[bytes] = ..., signature: _Optional[bytes] = ..., signer_key_id: _Optional[str] = ..., published_at_unix: _Optional[int] = ..., expires_at_unix: _Optional[int] = ..., is_heartbeat: bool = ...) -> None: ...

class AckRequest(_message.Message):
    __slots__ = ("node", "bundle_id", "applied_version", "ack_status", "detail")
    NODE_FIELD_NUMBER: _ClassVar[int]
    BUNDLE_ID_FIELD_NUMBER: _ClassVar[int]
    APPLIED_VERSION_FIELD_NUMBER: _ClassVar[int]
    ACK_STATUS_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    node: NodeIdentity
    bundle_id: str
    applied_version: str
    ack_status: str
    detail: str
    def __init__(self, node: _Optional[_Union[NodeIdentity, _Mapping]] = ..., bundle_id: _Optional[str] = ..., applied_version: _Optional[str] = ..., ack_status: _Optional[str] = ..., detail: _Optional[str] = ...) -> None: ...

class AckResponse(_message.Message):
    __slots__ = ("audit_id",)
    AUDIT_ID_FIELD_NUMBER: _ClassVar[int]
    audit_id: str
    def __init__(self, audit_id: _Optional[str] = ...) -> None: ...

class PublishRequest(_message.Message):
    __slots__ = ("bundle", "admin_token")
    BUNDLE_FIELD_NUMBER: _ClassVar[int]
    ADMIN_TOKEN_FIELD_NUMBER: _ClassVar[int]
    bundle: SignedBundle
    admin_token: str
    def __init__(self, bundle: _Optional[_Union[SignedBundle, _Mapping]] = ..., admin_token: _Optional[str] = ...) -> None: ...

class PublishResponse(_message.Message):
    __slots__ = ("bundle_id", "fleet_recipient_count", "audit_id")
    BUNDLE_ID_FIELD_NUMBER: _ClassVar[int]
    FLEET_RECIPIENT_COUNT_FIELD_NUMBER: _ClassVar[int]
    AUDIT_ID_FIELD_NUMBER: _ClassVar[int]
    bundle_id: str
    fleet_recipient_count: int
    audit_id: str
    def __init__(self, bundle_id: _Optional[str] = ..., fleet_recipient_count: _Optional[int] = ..., audit_id: _Optional[str] = ...) -> None: ...

class HealthzRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HealthzResponse(_message.Message):
    __slots__ = ("status", "active_subscribers", "active_bundles")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_SUBSCRIBERS_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_BUNDLES_FIELD_NUMBER: _ClassVar[int]
    status: str
    active_subscribers: int
    active_bundles: int
    def __init__(self, status: _Optional[str] = ..., active_subscribers: _Optional[int] = ..., active_bundles: _Optional[int] = ...) -> None: ...

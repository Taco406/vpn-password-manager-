//! Native-messaging protocol and framing, shared by the Chrome extension, the
//! native-messaging host, and the desktop IPC server. The trust boundary is the
//! desktop: it validates the requesting page origin against each item's saved URL
//! before releasing any field, and while locked returns zero credential data.

pub mod framing;
pub mod protocol;

pub use framing::{decode_frame, encode_frame, FrameError, MAX_MESSAGE_BYTES};
pub use protocol::{
    NmEnvelope, NmError, NmErrorCode, NmType, StatusEvent, VaultFieldsGetRequest,
    VaultSearchRequest, VaultSearchResultItem,
};

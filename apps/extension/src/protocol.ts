// Re-export the shared native-messaging protocol types (single source of truth,
// mirrored by the Rust `nm::protocol`).
export type {
  NmEnvelope,
  NmType,
  NmErrorCode,
  VaultSearchRequest,
  VaultSearchResultItem,
  VaultFieldsGetRequest,
  StatusEvent,
} from "@sentinel/shared";
export { NM_HOST_NAME, NM_MAX_MESSAGE_BYTES } from "@sentinel/shared";

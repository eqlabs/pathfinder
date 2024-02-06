/// Constants that allow us to estimate the maximum payload of certain types of messages
/// Maximum size of an encoded protobuf message in bytes
// FIXME: class related responses are limited to 4MiB, others 1MiB
pub const MESSAGE_SIZE_LIMIT: usize = 20 * 1024 * 1024;

//! XDP maps.
mod cpu_map;
mod dev_map;
mod dev_map_hash;
mod xsk_map;

pub use cpu_map::CpuMap;
pub use dev_map::DevMap;
pub use dev_map_hash::DevMapHash;
use thiserror::Error;
pub use xsk_map::XskMap;

use super::MapError;

#[derive(Error, Debug)]
/// Errors occurring from working with XDP maps.
pub enum XdpMapError {
    /// Chained programs are not supported.
    #[error("chained programs are not supported by the current kernel")]
    ChainedProgramNotSupported,

    /// Map operation failed.
    #[error(transparent)]
    MapError(#[from] MapError),
}

/// Returns whether the map's values have the chained-program layout `V`.
///
/// The kernel accepts this larger value only when it supports chained programs, so the map's
/// own value size decides the layout. This holds for maps created by any process, including
/// maps opened from a pin, an id, or a received descriptor.
const fn has_chained_program<V>(map: &super::MapData) -> bool {
    map.obj.value_size() as usize == size_of::<V>()
}

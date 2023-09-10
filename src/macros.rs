macro_rules! cfg_alloc {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "alloc")]
            $item
        )*
    }
}

macro_rules! cfg_stack {
    ($($item:item)*) => {
        $(
            #[cfg(not(feature = "alloc"))]
            $item
        )*
    }
}

macro_rules! cfg_encryption {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "encryption")]
            $item
        )*
    }
}

macro_rules! cfg_seek {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "seek")]
            $item
        )*
    }
}

pub(crate) use cfg_alloc;
pub(crate) use cfg_encryption;
pub(crate) use cfg_seek;
pub(crate) use cfg_stack;

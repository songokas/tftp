macro_rules! cfg_no_std {
    ($($item:item)*) => {
        $(
            #[cfg(not(feature = "std"))]
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

pub(crate) use cfg_encryption;
pub(crate) use cfg_no_std;

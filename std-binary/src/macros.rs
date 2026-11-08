macro_rules! cfg_encryption {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "encryption")]
            $item
        )*
    }
}

pub(crate) use cfg_encryption;

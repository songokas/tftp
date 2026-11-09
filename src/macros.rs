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

pub(crate) use cfg_alloc;
pub(crate) use cfg_stack;

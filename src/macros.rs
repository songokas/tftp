macro_rules! cfg_alloc {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "alloc")]
            $item
        )*
    }
}

macro_rules! cfg_stack_many_clients {
    ($($item:item)*) => {
        $(
            #[cfg(all(not(feature = "alloc"), not(feature = "stack_large_window")))]
            $item
        )*
    }
}

macro_rules! cfg_stack_large_window {
    ($($item:item)*) => {
        $(
            #[cfg(feature = "stack_large_window")]
            $item
        )*
    }
}

pub(crate) use cfg_alloc;
pub(crate) use cfg_stack_large_window;
pub(crate) use cfg_stack_many_clients;

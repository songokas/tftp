pub type BinError = Box<dyn std::error::Error + Sync + Send>;
pub type BinResult<T> = Result<T, BinError>;

pub mod core;
pub mod validator;

pub use actix_web_auth_macros::authorize;
pub use validator::AuthValidator;
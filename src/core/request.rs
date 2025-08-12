use actix_web::HttpRequest;

pub trait Request {
    fn auth_token(&self) -> anyhow::Result<&str>;
}

impl Request for HttpRequest {
    fn auth_token(&self) -> anyhow::Result<&str> {
        // Извлекаем токен из заголовка Authorization
        let auth_header = match self.headers().get("Authorization") {
            Some(header) => match header.to_str() {
                Ok(header_str) => header_str,
                Err(_) => return Err(anyhow::anyhow!("Invalid Authorization header format")),
            },
            None => return Err(anyhow::anyhow!("Missing Authorization header")),
        };
        
        // Проверяем формат "Bearer <token>"
        let token = if auth_header.starts_with("Bearer ") {
            &auth_header[7..]
        } else {
            return Err(anyhow::anyhow!("Authorization header must start with 'Bearer '"));
        };

        Ok(token)
    }
}
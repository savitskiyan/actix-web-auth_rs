use actix_web::HttpRequest;
use serde_json::Value;

pub trait AuthToken {
    fn auth_token(&self) -> anyhow::Result<&str>;
}

#[derive(Debug, Clone)]
pub struct Claim {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub claims: Vec<Claim>,
}


pub trait AuthIdentity {
    fn identity(&self) -> anyhow::Result<Identity>;
}

impl AuthToken for HttpRequest {
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

impl AuthIdentity for HttpRequest {
    fn identity(&self) -> anyhow::Result<Identity> {
        // 1. Извлекаем токен из заголовка Authorization
        let token = match self.auth_token() {
            Ok(token) => token,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to get authorization token. {}", err));
            }
        };
        // 2. извлекаем JWT часть токена как JSON и преобразуем в массив Claim, которая содержит claims
        let parts: Vec<&str> = token.rsplitn(2, '.').collect();
        let message = parts.get(0).ok_or_else(|| anyhow::anyhow!("Invalid JWT format"))?;
        let message_parts: Vec<&str> = message.rsplitn(2, '.').collect();
        let payload = message_parts.get(0).ok_or_else(|| anyhow::anyhow!("Invalid JWT format"))?;
        
        let obj = match serde_json::from_str::<Value>(payload) {
            Ok(obj) => obj,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to decode JWT claims. {}", err));
            }
        };
        let mut claims = Vec::<Claim>::new();
        // 3. преобразуем JSON в массив Claim
        if let Some(obj_map) = obj.as_object() {
            for (key, value) in obj_map {
                claims.push(Claim { 
                    name: key.to_string(), 
                    value: value.to_string() 
                });
            }
        }

        Ok(Identity { claims: claims })
    }
}
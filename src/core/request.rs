use std::str::FromStr;
use actix_web::HttpRequest;
use serde_json::Value;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

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
    claims: Vec<Claim>,
}

impl Identity {
    pub fn claims(&self) -> &Vec<Claim> {
        &self.claims
    }

    pub fn get_claim(&self, name: &str) -> Option<&Claim> {
        self.claims.iter().find(|claim| claim.name == name)
    }

    pub fn get_claim_value<T: FromStr>(&self, name: &str) -> anyhow::Result<T> {
        let claim = self.get_claim(name)
            .ok_or_else(|| anyhow::anyhow!("Claim '{}' not found", name))?;

        if claim.value.is_empty() {
            return Err(anyhow::anyhow!("Claim '{}' is empty", name));
        }

        claim.value.parse::<T>()
            .map_err(|_| anyhow::anyhow!("Claim '{}': is not a type of '{}'. Value: '{}'", name, claim.value, std::any::type_name::<T>()))
    }
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
        
        // 2. Разбиваем JWT токен на части (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid JWT format: expected 3 parts"));
        }
        
        // 3. Декодируем Base64 payload
        let payload = parts[1];
        let decoded_payload = match URL_SAFE_NO_PAD.decode(payload) {
            Ok(decoded) => decoded,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to decode JWT payload from Base64. {}", err));
            }
        };
        
        // 4. Парсим декодированный payload как JSON
        let payload_str = match String::from_utf8(decoded_payload) {
            Ok(s) => s,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to convert decoded payload to string. {}", err));
            }
        };
        
        let obj = match serde_json::from_str::<Value>(&payload_str) {
            Ok(obj) => obj,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to decode JWT claims. {}", err));
            }
        };
        
        let mut claims = Vec::<Claim>::new();
        // 5. Преобразуем JSON в массив Claim
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
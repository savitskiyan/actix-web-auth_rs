use std::fs;
use std::path::Path;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use anyhow;
use serde::{Deserialize};
use serde_yaml;
use serde_json::Value;
use actix_web::{error::Error, web, App, HttpRequest};
use actix_web::dev::{ServiceFactory, ServiceRequest};
use jsonwebtoken::{decode, decode_header, Validation};
use crate::core::request::Request;

/// Конфигурация политики доступа
#[derive(Deserialize, Debug, Clone)]
pub struct Policy {
    #[serde(default)]
    pub permissions: Vec<Vec<String>>,
}

/// Кэш валидатора авторизации
#[derive(Debug, Clone)]
struct AuthValidatorCache
{
    // конфигурация сервера авторизации
    openid_config: Option<Value>,
    // время последней загрузки конфигурации сервера авторизации
    openid_config_last_loaded: Option<SystemTime>,
    // конфигурация JWKS сервера авторизации
    jwks: Option<Value>,
    // время последней загрузки конфигурации JWKS сервера авторизации
    jwks_last_loaded: Option<SystemTime>,
    // политики доступа
    policies: HashMap<String, Policy>,
}

/// Конфигурация авторизации
#[derive(Debug, Clone)]
pub struct AuthValidator {
    // URL сервера авторизации
    issuer: String,
    // аудитории токена
    audiences: Vec<String>,
    // client_id токена
    client_id: Option<String>,
    // client_secret токена
    client_secret: Option<String>,
    // scopes токена
    scopes: Vec<String>,
    // кэш валидатора авторизации
    cache: Arc<RwLock<AuthValidatorCache>>,
}

impl AuthValidator {
    /// Создаёт новый экземпляр валидатора авторизации
    pub async fn new (issuer: String) -> anyhow::Result<Self> {

        // создаём объект валидатора авторизации
        let validator = AuthValidator {
            issuer,
            audiences: vec![],
            client_id: None,
            client_secret: None,
            scopes: vec![],
            cache: Arc::new(RwLock::new(AuthValidatorCache {
                openid_config: None,
                openid_config_last_loaded: None,
                jwks: None,
                jwks_last_loaded: None,
                policies: HashMap::new(),
            })),
        };

        // загружаем политики из файла
        match validator.load_policies("policies.yaml") {
            Ok(policies) => policies,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to load policies. {}", err));
            }
        };
        match validator.load_openid_config().await {
            Ok(_) => (),
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to load openid-configuration. {}", err));
            }
        };
        match validator.load_jwks().await {
            Ok(_) => (),
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to load JWKS. {}", err));
            }
        }
        
        Ok(validator)
    }

    /// Устанавливает аудиторию
    pub fn set_audience(&mut self, audiences: Vec<String>) {
        self.audiences = audiences;
    }

    /// Устанавливает client_id
    pub fn set_client_id(&mut self, client_id: String) {
        self.client_id = Some(client_id);
    }

    /// Устанавливает client_secret
    pub fn set_client_secret(&mut self, client_secret: String) {
        self.client_secret = Some(client_secret);
    }

    /// Устанавливает scopes
    pub fn set_scopes(&mut self, scopes: Vec<String>) {
        self.scopes = scopes;
    }

    /// Загружает политики из файла
    fn load_policies(&self, file_name: &str) -> anyhow::Result<()> {
        // проверяем, что путь к файлу конфигурации не пустой
        if file_name.is_empty() {
            return Err(anyhow::anyhow!("File name is empty."));
        }
        // проверяем, что файл конфигурации существует
        if !Path::new(file_name).exists() {
            return Err(anyhow::anyhow!("File not found: {}.", file_name));
        }
        // загружаем политики из файла
        let file = match fs::File::open(file_name) {
            Ok(file) => file,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to open file. {}", err));
            }
        };
        // парсим политики из файла
        let policies: HashMap<String, Policy> = match serde_yaml::from_reader(file) {
            Ok(policies) => policies,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to parse policies. {}", err));
            }
        };
        
        // Сохраняем политики в кеш
        {
            let mut cache = self.cache.write().unwrap();
            cache.policies = policies;
        }
        
        Ok(())
    }

    /// Загружает openid-конфигурацию сервера авторизации
    async fn load_openid_config(&self) -> anyhow::Result<()> {
        // проверяем, надо ли загружать openid-конфигурацию:
        // - если конфигурация ещё не была загружена
        // - если конфигурация была загружена более 3 минут назад
        let can_load = {
            let cache = self.cache.read().unwrap();
            cache.openid_config.is_none() || 
            cache.openid_config_last_loaded
                .map(|t| t.elapsed().unwrap_or(Duration::MAX) > Duration::from_secs(180))
                .unwrap_or(true)
        };

        if can_load {
            // проверяем, что issuer не пустой
            if self.issuer.is_empty() {
                return Err(anyhow::anyhow!("Issuer is empty."));
            }
            // формируем URL для запроса openid-конфигурации
            let url = format!("{}/.well-known/openid-configuration", self.issuer.trim_end_matches('/'));

            log::trace!("Loading openid-configuration from: {}", url);
            // выполняем запрос к openid-конфигурации
            let response = match reqwest::get(url).await {
                Ok(response) => response,
                Err(err) => {
                    return Err(anyhow::anyhow!("Failed to load openid-configuration. {}", err));
                }
            };
            
            // парсим ответ в JSON
            let config = match response.json::<Value>().await {
                Ok(json) => json,
                Err(err) => {
                    return Err(anyhow::anyhow!("Failed to parse openid-configuration. {}", err));
                }
            };

            // сохраняем в кеш
            {
                let mut cache = self.cache.write().unwrap();
                cache.openid_config = Some(config);
                cache.openid_config_last_loaded = Some(SystemTime::now());
            }
        }
        Ok(())
    }

    /// Загружает JWKS сервера авторизации
    async fn load_jwks(&self) -> anyhow::Result<()> {
        // проверяем, надо ли загружать jwks-конфигурацию:
        // - если конфигурация ещё не была загружена
        // - если конфигурация была загружена более 3 минут назад
        let can_load = {
            let cache = self.cache.read().unwrap();
            cache.jwks.is_none() || 
            cache.jwks_last_loaded
                .map(|t| t.elapsed().unwrap_or(Duration::MAX) > Duration::from_secs(180))
                .unwrap_or(true)
        };

        // проверяем, надо ли обновить jwks-конфигурацию
        if can_load {
            // сначала загружаем openid-конфигурацию если нужно
            match self.load_openid_config().await {
                Ok(_) => (),
                Err(err) => {
                    return Err(anyhow::anyhow!("Failed to load openid-configuration. {}", err));
                }
            }

            // получаем URL для запроса JWKS из кеша
            let url = {
                let cache = self.cache.read().unwrap();
                match cache.openid_config.as_ref() {
                    Some(config) => {
                        match config.get("jwks_uri").and_then(|uri| uri.as_str()) {
                            Some(url) => url.to_string(),
                            None => {
                                return Err(anyhow::anyhow!("Invalid openid-configuration: missing 'jwks_uri'."));
                            }
                        }
                    },
                    None => {
                        return Err(anyhow::anyhow!("OpenID configuration not loaded"));
                    }
                }
            };
            
            // выполняем запрос к JWKS серверу
            let response = match reqwest::get(url).await {
                Ok(response) => response,
                Err(err) => {
                    return Err(anyhow::anyhow!("Failed to load JWKS. {}", err));
                }
            };

            // парсим ответ в JSON
            let jwks = match response.json::<Value>().await {
                Ok(json) => json,
                Err(err) => {
                    return Err(anyhow::anyhow!("Failed to parse JWKS. {}", err));
                }
            };

            // сохраняем в кеш
            {
                let mut cache = self.cache.write().unwrap();
                cache.jwks = Some(jwks);
                cache.jwks_last_loaded = Some(SystemTime::now());
            }
        }
        Ok(())
    }

    async fn get_jwk_key_json_by_kid(&self, key_id: &str) -> anyhow::Result<Value> {
        // загружаем JWKS если нужно
        match self.load_jwks().await {
            Ok(_) => (),
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to load JWKS. {}", err));
            }
        }

        // получаем JWKS из кеша
        let jwks = {
            let cache = self.cache.read().unwrap();
            match cache.jwks.as_ref() {
                Some(jwks) => jwks.clone(),
                None => {
                    return Err(anyhow::anyhow!("JWKS not loaded"));
                }
            }
        };

        let keys = match jwks.get("keys") {
            Some(keys) => keys,
            None => {
                return Err(anyhow::anyhow!("Invalid JWKS format: missing 'keys' array."));
            }
        };
        let vec_keys = match keys.as_array() {
            Some(keys) => keys.to_vec(),
            None => {
                return Err(anyhow::anyhow!("Invalid JWKS format: 'keys' is not an array."));
            }
        };

        // Ищем ключ по kid или используем первый доступный
        let key_data = vec_keys.iter().find(|key| {
            key.get("kid").and_then(|k| k.as_str()) == Some(key_id)
        });
        
        let key_json = match key_data {
            Some(key) => key,
            None => {
                return Err(anyhow::anyhow!("No matching key found in JWKS."));
            }
        };
        Ok(key_json.clone())
    }

    async fn get_jwk_key_json_by_alg(&self, alg: &str) -> anyhow::Result<Value> {
        // загружаем JWKS если нужно
        match self.load_jwks().await {
            Ok(_) => (),
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to load JWKS. {}", err));
            }
        }

        // получаем JWKS из кеша
        let jwks = {
            let cache = self.cache.read().unwrap();
            match cache.jwks.as_ref() {
                Some(jwks) => jwks.clone(),
                None => {
                    return Err(anyhow::anyhow!("JWKS not loaded"));
                }
            }
        };

        let keys = match jwks.get("keys") {
            Some(keys) => keys,
            None => {
                return Err(anyhow::anyhow!("Invalid JWKS format: missing 'keys' array."));
            }
        };
        let vec_keys = match keys.as_array() {
            Some(keys) => keys.to_vec(),
            None => {
                return Err(anyhow::anyhow!("Invalid JWKS format: 'keys' is not an array."));
            }
        };

        // Ищем ключ по kid или используем первый доступный
        let key_data = vec_keys.iter().find(|key| {
            key.get("alg").and_then(|k| k.as_str()) == Some(alg)
        });
        
        let key_json = match key_data {
            Some(key) => key,
            None => {
                return Err(anyhow::anyhow!("No matching key found in JWKS."));
            }
        };
        Ok(key_json.clone())
    }

    /// Проверяет JWT токен из HttpRequest
    pub async fn validate(&self, req: &HttpRequest) -> bool {
        // 1. Извлекаем токен из заголовка Authorization
        let token = match req.auth_token() {
            Ok(token) => token,
            Err(err) => {
                log::warn!("Failed to get authorization token. {}", err);
                return false;
            }
        };
        
        // 2. Декодируем заголовок JWT для получения алгоритма и kid
        let header = match decode_header(token) {
            Ok(header) => header,
            Err(err) => {
                log::warn!("Failed to decode JWT header. {}", err);
                return false;
            }
        };

        let key_json = match header.kid {
            Some(kid) => {
                match self.get_jwk_key_json_by_kid(&kid).await {
                    Ok(key) => key,
                    Err(err) => {
                        log::warn!("Failed to get JWKS key. {}", err);
                        return false;
                    }
                }
            }
            None => {
                match self.get_jwk_key_json_by_alg(format!("{:?}", header.alg).as_str()).await {
                    Ok(key) => key,
                    Err(err) => {
                        log::warn!("Failed to get JWKS key. {}", err);
                        return false;
                    }
                }
            }
        };
        // if header.kid.is_none() {
        //     log::warn!("JWT header has no kid");
        //     return false;
        // }
        
        // Ищем ключ по kid
        // let key_json = match self.get_jwk_key_json_by_kid(header.kid.as_ref().unwrap()).await {
        //     Ok(key) => key,
        //     Err(err) => {
        //         log::warn!("Failed to get JWKS key. {}", err);
        //         return false;
        //     }
        // };
        
        // Извлекаем публичный ключ
        let decoding_key = match self.extract_decoding_key(&key_json) {
            Ok(key) => key,
            Err(err) => {
                log::warn!("Failed to extract decoding key. {}", err);
                return false;
            }
        };
        
        // 4. Настраиваем валидацию
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        
        // Если указаны audiences, добавляем их в валидацию
        if !self.audiences.is_empty() {
            validation.set_audience(&self.audiences.iter().map(|s| s.as_str()).collect::<Vec<_>>());
        } else {
            validation.validate_aud = false;
        }
        
        // 5. Декодируем и валидируем токен
        let token_data = match decode::<Value>(token, &decoding_key, &validation) {
            Ok(data) => data,
            Err(err) => {
                log::warn!("JWT validation failed. {}", err);
                return false;
            }
        };
        
        // 6. Дополнительная проверка scopes если они указаны
        if !self.scopes.is_empty() {
            let token_scopes = token_data.claims
                .get("scope")
                .or_else(|| token_data.claims.get("scp"))
                .and_then(|s| {
                    if let Some(scope_str) = s.as_str() {
                        Some(scope_str.split_whitespace().collect::<Vec<_>>())
                    } else if let Some(scope_array) = s.as_array() {
                        Some(scope_array.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            
            // Проверяем, что токен содержит хотя бы один из требуемых scopes
            let has_required_scope = self.scopes.iter().any(|required_scope| {
                token_scopes.contains(&required_scope.as_str())
            });
            
            if !has_required_scope {
                log::warn!("Token missing required scopes. Required: {:?}, Found: {:?}", self.scopes, token_scopes);
                return false;
            }
        }
        
        log::debug!("JWT token validation successful");
        true
    }
    
    /// Извлекает ключ для декодирования из JWKS
    fn extract_decoding_key(&self, key_json: &serde_json::Value) -> anyhow::Result<jsonwebtoken::DecodingKey> {
        use jsonwebtoken::DecodingKey;
        use base64::{Engine as _, engine::general_purpose};
        
        let kty = key_json.get("kty")
            .and_then(|k| k.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'kty' in key"))?;
        
        match kty {
            "RSA" => {
                let n = key_json.get("n")
                    .and_then(|n| n.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'n' in RSA key"))?;
                let e = key_json.get("e")
                    .and_then(|e| e.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'e' in RSA key"))?;
                
                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| anyhow::anyhow!("Failed to create RSA key: {}", e))
            }
            "EC" => {
                let x = key_json.get("x")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'x' in EC key"))?;
                let y = key_json.get("y")
                    .and_then(|y| y.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'y' in EC key"))?;
                
                DecodingKey::from_ec_components(x, y)
                    .map_err(|e| anyhow::anyhow!("Failed to create EC key: {}", e))
            }
            "oct" => {
                let k = key_json.get("k")
                    .and_then(|k| k.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing 'k' in symmetric key"))?;
                
                let key_bytes = general_purpose::URL_SAFE_NO_PAD
                    .decode(k)
                    .map_err(|e| anyhow::anyhow!("Failed to decode symmetric key: {}", e))?;
                
                Ok(DecodingKey::from_secret(&key_bytes))
            }
            _ => Err(anyhow::anyhow!("Unsupported key type. {}", kty))
        }
    }



    /// Проверяет политику доступа из HttpRequest
    pub async fn check_policy(&self, policy_name: &str, req: &HttpRequest) -> bool {
        // Получаем политику по имени из кеша
        let policy = {
            let cache = self.cache.read().unwrap();
            match cache.policies.get(policy_name) {
                Some(policy) => policy.clone(),
                None => {
                    log::warn!("Policy '{}' not found", policy_name);
                    return false;
                }
            }
        };
        
        // Если политика пустая (нет permissions), разрешаем доступ
        if policy.permissions.is_empty() {
            log::debug!("Policy '{}' has no permissions requirements.", policy_name);
            return true;
        }
        
        // 1. Извлекаем токен из заголовка Authorization
        let token = match req.auth_token() {
            Ok(token) => token,
            Err(err) => {
                log::warn!("Failed to get authorization token. {}", err);
                return false;
            }
        };
        
        // 2. Декодируем заголовок JWT для получения алгоритма и kid
        let header = match decode_header(token) {
            Ok(header) => header,
            Err(err) => {
                log::warn!("Failed to decode JWT header. {}", err);
                return false;
            }
        };

        if header.kid.is_none() {
            log::warn!("JWT header has no kid.");
            return false;
        }
        
        // Декодируем токен без проверки подписи (подпись уже проверена в validate)
        let mut validation = Validation::new(header.alg);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        validation.validate_aud = false;
        
        // Используем фиктивный ключ так как проверка подписи отключена
        let dummy_key = jsonwebtoken::DecodingKey::from_secret(&[]);
        
        let token_data = match decode::<Value>(token, &dummy_key, &validation) {
            Ok(data) => data,
            Err(err) => {
                log::warn!("Failed to decode JWT for policy check. {}", err);
                return false;
            }
        };
        
        // Извлекаем разрешения пользователя из различных полей токена
        let user_permissions = self.extract_user_permissions(&token_data.claims);
        
        // Проверяем каждый список в политике:
        // - хотя бы один пермишен пользователя должен быть в каждом списке пермишенов из политики
        policy.permissions.iter().all(|group| {
            group.iter().any(|perm| user_permissions.contains(perm))
        })
    }
    
    /// Извлекает разрешения пользователя из claims JWT токена
    fn extract_user_permissions(&self, claims: &serde_json::Value) -> Vec<String> {
        let mut permissions = Vec::new();
        
        // Проверяем различные поля где могут храниться разрешения
        let permission_fields = ["permissions", "perms", "authorities", "roles", "scope", "scp"];
        
        for field in &permission_fields {
            if let Some(value) = claims.get(field) {
                match value {
                    // Массив строк
                    serde_json::Value::Array(arr) => {
                        for item in arr {
                            if let Some(perm) = item.as_str() {
                                permissions.push(perm.to_string());
                            }
                        }
                    }
                    // Строка с разделителями (обычно пробел для scope)
                    serde_json::Value::String(s) => {
                        if field == &"scope" || field == &"scp" {
                            // Для scope разделяем по пробелам
                            permissions.extend(s.split_whitespace().map(|s| s.to_string()));
                        } else {
                            // Для других полей добавляем как одно разрешение
                            permissions.push(s.clone());
                        }
                    }
                    _ => {
                        log::debug!("Unsupported permission field format for '{}': {:?}.", field, value);
                    }
                }
            }
        }
        
        // Удаляем дубликаты
        permissions.sort();
        permissions.dedup();
        
        log::debug!("Extracted user permissions: {:?}.", permissions);
        permissions
    }
}

/// Методы для работы с конфигурацией авторизации
pub trait ActixAppAuthValidator {
    /// Конфигурирует приложение для работы с авторизацией
    fn configure_auth(self, validator: AuthValidator) -> Self;
}

/// Реализация методов для работы с конфигурацией авторизации
impl<T> ActixAppAuthValidator for App<T>
where
    T: ServiceFactory<ServiceRequest, Config = (), Error = Error, InitError = ()>,
{
    /// Конфигурирует приложение для работы с авторизацией
    fn configure_auth(mut self, validator: AuthValidator) -> Self {
        // добавляем валидатор авторизации в app_data
        log::debug!("Authorization configure.");
        self = self.app_data(web::Data::new(validator));
        log::debug!("Authorization configure done.");
        self
    }
}
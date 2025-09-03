use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, LitStr, parse::Parse, parse::ParseStream};

/// Структура для парсинга аргументов макроса
struct AuthorizeArgs {
    policy: Option<LitStr>,
}

impl Parse for AuthorizeArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Проверяем, есть ли аргументы
        if input.is_empty() {
            // Нет аргументов - только проверка токена
            Ok(AuthorizeArgs { policy: None })
        } else {
            // Есть аргументы - парсим политику
            let policy: LitStr = input.parse()?;
            Ok(AuthorizeArgs { policy: Some(policy) })
        }
    }
}

/// Макрос атрибута для авторизации
/// 
/// Использование:
/// ```
/// use actix_web::{get, post, web, HttpResponse};
/// use actix_web_auth::authorize;
/// 
/// // Функция БЕЗ параметров - работает как есть
/// #[authorize]
/// #[get("/version")]
/// async fn get_version() -> HttpResponse {
///     HttpResponse::Ok().finish()
/// }
/// 
/// // Функция С параметрами - работает как есть
/// #[authorize("users.create")]
/// #[post("/users")]
/// async fn create_user(data: web::Json<MyData>) -> HttpResponse {
///     HttpResponse::Created().json("User created")
/// }
/// ```
/// 
/// Требования:
/// - В app_data должен быть зарегистрирован AuthValidator
/// - AuthValidator должен иметь методы validate(&ServiceRequest) -> bool и check_policy(&str, &ServiceRequest) -> bool
/// - Функция сохраняет свою оригинальную сигнатуру БЕЗ ИЗМЕНЕНИЙ
#[proc_macro_attribute]
pub fn authorize(args: TokenStream, input: TokenStream) -> TokenStream {
    // Парсим аргументы макроса
    let args = parse_macro_input!(args as AuthorizeArgs);
    
    // Парсим функцию, к которой применяется макрос
    let input_fn = parse_macro_input!(input as ItemFn);
    
    let fn_vis = &input_fn.vis;
    let fn_sig = &input_fn.sig;
    let fn_block = &input_fn.block;
    let fn_attrs = &input_fn.attrs;
    let fn_name = &fn_sig.ident;
    let fn_inputs = &fn_sig.inputs;
    let fn_output = &fn_sig.output;
    
    // Создаем имя для внутренней функции с оригинальной логикой
    let inner_fn_name = syn::Ident::new(&format!("__inner_{}", fn_name), fn_name.span());
    
    // Проверяем, есть ли уже HttpRequest среди параметров и находим его имя
    let http_request_param = fn_inputs.iter().find_map(|input| {
        if let syn::FnArg::Typed(pat_type) = input {
            if let syn::Type::Path(type_path) = &*pat_type.ty {
                if type_path.path.segments.last()
                    .map(|seg| seg.ident == "HttpRequest")
                    .unwrap_or(false)
                {
                    if let syn::Pat::Ident(ident) = &*pat_type.pat {
                        return Some(&ident.ident);
                    }
                }
            }
        }
        None
    });
    
    // Извлекаем имена параметров для передачи в оригинальную функцию
    let param_names: Vec<_> = fn_inputs.iter().filter_map(|input| {
        if let syn::FnArg::Typed(pat_type) = input {
            if let syn::Pat::Ident(ident) = &*pat_type.pat {
                Some(&ident.ident)
            } else {
                None
            }
        } else {
            None
        }
    }).collect();
    
    // Генерируем wrapper функцию с проверкой авторизации
    let expanded = if let Some(req_param) = http_request_param {
        // Если HttpRequest уже есть в параметрах, используем оригинальную сигнатуру
        let policy_check = if let Some(policy) = &args.policy {
            let policy_name = policy.value();
            quote! {
                // Проверяем политику
                let policy_name = #policy_name;
                if !validator.check_policy(policy_name, &#req_param).await {
                    log::warn!("Access denied: policy '{}' not satisfied.", policy_name);
                    return actix_web::HttpResponse::Unauthorized().finish();
                }
            }
        } else {
            quote! {
                // Политика не указана - пропускаем проверку политики
            }
        };

        quote! {
            // Внутренняя функция с оригинальной логикой (без изменений)
            async fn #inner_fn_name(#fn_inputs) #fn_output #fn_block
            
            // Обёрнутая функция-обработчик с проверкой авторизации
            #(#fn_attrs)*
            #fn_vis async fn #fn_name(#fn_inputs) -> actix_web::HttpResponse {
                use actix_web::web;
                
                // Получаем валидатор авторизации из app_data  
                let validator = match #req_param.app_data::<web::Data<AuthValidator>>() {
                    Some(v) => v,
                    None => {
                        log::warn!("Authorization validator not configured.");
                        return actix_web::HttpResponse::Unauthorized().finish();
                    }
                };
                
                // Проверяем JWT токен
                if !validator.validate(&#req_param).await {
                    log::warn!("Access denied: invalid or expired token.");
                    return actix_web::HttpResponse::Unauthorized().finish();
                }
                
                // Условная проверка политики
                #policy_check
                
                // Если все проверки прошли успешно, выполняем оригинальную функцию
                #inner_fn_name(#(#param_names),*).await
            }
        }
    } else {
        // Если HttpRequest НЕТ в параметрах, добавляем его как первый параметр
        let policy_check = if let Some(policy) = &args.policy {
            let policy_name = policy.value();
            quote! {
                // Проверяем политику
                let policy_name = #policy_name;
                if !validator.check_policy(policy_name, &req).await {
                    log::warn!("Access denied: policy '{}' not satisfied.", policy_name);
                    return actix_web::HttpResponse::Unauthorized().finish();
                }
            }
        } else {
            quote! {
                // Политика не указана - пропускаем проверку политики
            }
        };

        quote! {
            // Внутренняя функция с оригинальной логикой (без изменений)
            async fn #inner_fn_name(#fn_inputs) #fn_output #fn_block
            
            // Обёрнутая функция-обработчик с проверкой авторизации
            #(#fn_attrs)*
            #fn_vis async fn #fn_name(
                req: actix_web::HttpRequest,
                #fn_inputs
            ) -> actix_web::HttpResponse {
                use actix_web::web;
                
                // Получаем валидатор авторизации из app_data
                let validator = match req.app_data::<web::Data<AuthValidator>>() {
                    Some(v) => v,
                    None => {
                        log::warn!("Authorization validator not configured.");
                        return actix_web::HttpResponse::Unauthorized().finish();
                    }
                };
                
                // Проверяем JWT токен
                if !validator.validate(&req).await {
                    log::warn!("Access denied: invalid or expired token.");
                    return actix_web::HttpResponse::Unauthorized().finish();
                }
                
                // Условная проверка политики
                #policy_check
                
                // Если все проверки прошли успешно, выполняем оригинальную функцию
                #inner_fn_name(#(#param_names),*).await
            }
        }
    };
    
    TokenStream::from(expanded)
}

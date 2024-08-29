use crate::{
    api::auth,
    canon,
    context::Context,
    entity::{
        WorkspacesType, PARAMETER_NAME_HUGGING_FACE_TOKEN_ACCESS, PARAMETER_NAME_MAIN_LLM,
        PARAMETER_NAME_MAIN_LLM_ANTHROPIC_API_KEY, PARAMETER_NAME_MAIN_LLM_ANTHROPIC_MODEL,
        PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_API_KEY,
        PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_DEPLOYMENT_ID,
        PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_ENABLED, PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_URL,
        PARAMETER_NAME_MAIN_LLM_OLLAMA_MODEL, PARAMETER_NAME_MAIN_LLM_OPENAI_API_KEY,
        PARAMETER_NAME_MAIN_LLM_OPENAI_PRIMARY_MODEL,
        PARAMETER_NAME_MAIN_LLM_OPENAI_SECONDARY_MODEL, PARAMETER_NAME_MAIN_LLM_OPENAI_TEMPERATURE,
        PARAMETER_NAME_MAIN_LLM_SYSTEM_PROMPT, PARAMETER_NAME_NEXTCLOUD_PASSWORD,
        PARAMETER_NAME_NEXTCLOUD_URL, PARAMETER_NAME_NEXTCLOUD_USERNAME,
        PARAMETER_NAME_OCTOPUS_API_URL, PARAMETER_NAME_OCTOPUS_WS_URL,
        PARAMETER_NAME_REGISTRATION_ALLOWED, PARAMETER_NAME_SCRAPINGBEE_API_KEY,
        PARAMETER_NAME_SENDGRID_API_KEY, ROLE_COMPANY_ADMIN_USER, ROLE_PRIVATE_USER,
        ROLE_PUBLIC_USER,
    },
    error::AppError,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use std::sync::Arc;
use utoipa::ToSchema;
use validator::Validate;

#[derive(Clone, Debug)]
pub struct ExamplePrompt {
    pub prompt: String,
    pub title: String,
}

#[derive(Clone, Debug)]
pub struct ExamplePromptCategory {
    pub description: String,
    pub title: String,
    pub prompts: Vec<ExamplePrompt>,
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct SetupPost {
    #[validate(length(max = 256, min = 1))]
    company_name: String,
    #[validate(email, length(max = 256))]
    email: String,
    #[validate(length(min = 8))]
    password: String,
    #[validate(length(min = 8))]
    repeat_password: String,
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct SetupInfoResponse {
    registration_allowed: bool,
    setup_required: bool,
}

#[axum_macros::debug_handler]
#[utoipa::path(
    get,
    path = "/api/v1/setup",
    responses(
        (status = 200, description = "Setup info read.", body = SetupInfoResponse),
    ),
    security(
        ()
    )
)]
pub async fn info(State(context): State<Arc<Context>>) -> Result<impl IntoResponse, AppError> {
    let companies = context.octopus_database.get_companies().await?;
    let registration_allowed = context
        .get_config()
        .await?
        .get_parameter_registration_allowed()
        .unwrap_or(true);

    let setup_info_response = SetupInfoResponse {
        registration_allowed,
        setup_required: companies.is_empty(),
    };

    let mut transaction = context.octopus_database.transaction_begin().await?;

    create_missing_data(context.clone(), &mut transaction).await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    Ok((StatusCode::OK, Json(setup_info_response)).into_response())
}

#[axum_macros::debug_handler]
#[utoipa::path(
    post,
    path = "/api/v1/setup",
    request_body = SetupPost,
    responses(
        (status = 201, description = "Account created.", body = User),
        (status = 400, description = "Bad request.", body = ResponseError),
        (status = 409, description = "Conflicting request.", body = ResponseError),
    ),
    security(
        ()
    )
)]
pub async fn setup(
    State(context): State<Arc<Context>>,
    Json(input): Json<SetupPost>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    let email = canon::canonicalize(&input.email);

    let user_exists = context
        .octopus_database
        .try_get_user_by_email(&email)
        .await?;

    match user_exists {
        None => {
            if input.password != input.repeat_password {
                return Err(AppError::PasswordDoesNotMatch);
            }

            let cloned_password = input.password.clone();
            let config = context.get_config().await?;
            let pw_hash =
                tokio::task::spawn_blocking(move || auth::hash_password(&config, &cloned_password))
                    .await??;

            let mut transaction = context.octopus_database.transaction_begin().await?;

            let company = context
                .octopus_database
                .insert_company(&mut transaction, None, None, &input.company_name)
                .await?;

            let user = context
                .octopus_database
                .insert_user(
                    &mut transaction,
                    company.id,
                    &email,
                    true,
                    false,
                    context.get_config().await?.pepper_id,
                    &pw_hash,
                    &[
                        ROLE_COMPANY_ADMIN_USER.to_string(),
                        ROLE_PRIVATE_USER.to_string(),
                        ROLE_PUBLIC_USER.to_string(),
                    ],
                )
                .await?;

            context
                .octopus_database
                .insert_profile(&mut transaction, user.id, None, None)
                .await?;

            context
                .octopus_database
                .insert_workspace(
                    &mut transaction,
                    user.company_id,
                    user.id,
                    "Public Group",
                    WorkspacesType::Public,
                )
                .await?;

            create_missing_data(context.clone(), &mut transaction).await?;

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            Ok((StatusCode::CREATED, Json(user)).into_response())
        }
        Some(_user_exists) => Err(AppError::UserAlreadyExists),
    }
}

pub async fn create_missing_data(
    context: Arc<Context>,
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), AppError> {
    create_missing_example_prompts(context.clone(), transaction).await?;
    create_missing_parameters(context.clone(), transaction).await?;

    Ok(())
}

pub async fn create_missing_example_prompts(
    context: Arc<Context>,
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), AppError> {
    let example_prompts = context.octopus_database.get_example_prompts().await?;

    if example_prompts.is_empty() {
        let example_prompt_categories = get_example_prompt_categories();

        for example_prompt_category_tmp in example_prompt_categories {
            let example_prompt_category = context
                .octopus_database
                .insert_example_prompt_category(
                    transaction,
                    &example_prompt_category_tmp.description,
                    true,
                    &example_prompt_category_tmp.title,
                )
                .await?;

            for example_prompt_tmp in example_prompt_category_tmp.prompts {
                context
                    .octopus_database
                    .insert_example_prompt(
                        transaction,
                        example_prompt_category.id,
                        None,
                        true,
                        0,
                        &example_prompt_tmp.prompt,
                        &example_prompt_tmp.title,
                    )
                    .await?;
            }
        }
    }

    Ok(())
}

pub fn get_example_prompt_categories() -> Vec<ExamplePromptCategory> {
    vec![
        ExamplePromptCategory {
            description: "Addressing concerns about safety protocols, equipment maintenance, and health hazards in the factory environment.".to_string(),
            title: "Workplace Safety and Health".to_string(),
            prompts: vec![
                ExamplePrompt {
                    prompt: "What are the step-by-step procedures for handling chemical spills, and what measures should I take to ensure the safety of myself and my colleagues?".to_string(),
                    title: "Chemical Spill Response".to_string(),
                },
                ExamplePrompt {
                    prompt: "Can you provide a comprehensive guide on using personal protective equipment (PPE) effectively in various scenarios, emphasizing proper selection, usage, and maintenance?".to_string(),
                    title: "Effective PPE Usage".to_string(),
                },
                ExamplePrompt {
                    prompt: "I'd like to better understand the specific safety rules and guidelines that apply to operating [Specific Machinery/Equipment] in our factory. Could you provide a detailed overview?".to_string(),
                    title: "Machinery Safety Guidelines".to_string(),
                },
            ],
        },
        ExamplePromptCategory {
            description: "Problems with machinery, tools, or equipment not functioning correctly, requiring maintenance or repairs.".to_string(),
            title: "Technical Equipment Malfunctions".to_string(),
            prompts: vec![
                ExamplePrompt {
                    prompt: "There's a strange noise coming from [Specific Equipment] during operation, and I'm concerned about its impact on its performance. Can you help me diagnose the source of the noise and recommend remedies?".to_string(),
                    title: "Diagnosing and Rectifying Noise in [Specific Equipment]".to_string(),
                },
                ExamplePrompt {
                    prompt: "The [Specific Machine] seems to be operating slower than usual, affecting our production speed. Could you provide insights into potential causes for this slowdown and steps to improve its performance?".to_string(),
                    title: "Addressing Slow Performance in [Specific Machine]".to_string(),
                },
                ExamplePrompt {
                    prompt: "Our [Specific Equipment] suddenly shut down without warning, and we're not sure what caused it. Could you assist in identifying potential reasons for the shutdown and ways to prevent it in the future?".to_string(),
                    title: "Unplanned Shutdown of [Specific Equipment]".to_string(),
                },
            ],
        },
        ExamplePromptCategory {
            description: "Workers might need help with acquiring new skills, understanding new technologies, or improving their performance in their current roles.".to_string(),
            title: "Training and Skill Development".to_string(),
            prompts: vec![
                ExamplePrompt {
                    prompt: "I'm interested in advancing my skill set to better contribute to the team. Can you provide guidance on available training programs and resources that can help me develop relevant skills for my role?".to_string(),
                    title: "Exploring Skill Development Opportunities".to_string(),
                },
                ExamplePrompt {
                    prompt: "I'd like to learn more about the new technology being integrated into our processes. Could you recommend training courses or materials that can help me understand and work with these technological advancements?".to_string(),
                    title: "Navigating New Technology Training".to_string(),
                },
                ExamplePrompt {
                    prompt: "I've identified a gap in my proficiency with [Specific Software/Tool]. Are there training resources available that can assist me in improving my proficiency and effectiveness when using it?".to_string(),
                    title: "Improving Proficiency in [Specific Software/Tool]".to_string(),
                },
            ],
        },
        ExamplePromptCategory {
            description: "Seeking assistance with optimizing production processes, minimizing bottlenecks, and improving overall operational efficiency.".to_string(),
            title: "Workflow and Efficiency".to_string(),
            prompts: vec![],
        },
        ExamplePromptCategory {
            description: "Dealing with conflicts among colleagues or supervisors, addressing communication breakdowns, and maintaining a healthy working environment.".to_string(),
            title: "Interpersonal Conflicts".to_string(),
            prompts: vec![],
        },
        ExamplePromptCategory {
            description: "Seeking guidance on payroll, benefits, overtime, or disputes related to compensation.".to_string(),
            title: "Wages and Benefits".to_string(),
            prompts: vec![],
        },
        ExamplePromptCategory {
            description: "Workers may seek advice on career paths, skill development, and opportunities for growth within the organization.".to_string(),
            title: "Career Advancement".to_string(),
            prompts: vec![],
        },
        ExamplePromptCategory {
            description: "Striking a balance between work and personal life, managing shift schedules, and requesting time off.".to_string(),
            title: "Work-Life Balance".to_string(),
            prompts: vec![],
        },
        ExamplePromptCategory {
            description: "Understanding and adhering to industry regulations, environmental standards, and other legal requirements.".to_string(),
            title: "Compliance and Regulations".to_string(),
            prompts: vec![],
        },
    ]
}

pub async fn create_missing_parameters(
    context: Arc<Context>,
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), AppError> {
    let parameters = vec![
        PARAMETER_NAME_HUGGING_FACE_TOKEN_ACCESS,
        PARAMETER_NAME_MAIN_LLM,
        PARAMETER_NAME_MAIN_LLM_ANTHROPIC_API_KEY,
        PARAMETER_NAME_MAIN_LLM_ANTHROPIC_MODEL,
        PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_API_KEY,
        PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_DEPLOYMENT_ID,
        PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_ENABLED,
        PARAMETER_NAME_MAIN_LLM_AZURE_OPENAI_URL,
        PARAMETER_NAME_MAIN_LLM_OLLAMA_MODEL,
        PARAMETER_NAME_MAIN_LLM_OPENAI_API_KEY,
        PARAMETER_NAME_MAIN_LLM_OPENAI_PRIMARY_MODEL,
        PARAMETER_NAME_MAIN_LLM_OPENAI_SECONDARY_MODEL,
        PARAMETER_NAME_MAIN_LLM_OPENAI_TEMPERATURE,
        PARAMETER_NAME_MAIN_LLM_SYSTEM_PROMPT,
        PARAMETER_NAME_NEXTCLOUD_PASSWORD,
        PARAMETER_NAME_NEXTCLOUD_URL,
        PARAMETER_NAME_NEXTCLOUD_USERNAME,
        PARAMETER_NAME_OCTOPUS_API_URL,
        PARAMETER_NAME_OCTOPUS_WS_URL,
        PARAMETER_NAME_REGISTRATION_ALLOWED,
        PARAMETER_NAME_SCRAPINGBEE_API_KEY,
        PARAMETER_NAME_SENDGRID_API_KEY,
    ];

    for parameter_name in parameters {
        let parameter = context
            .octopus_database
            .try_get_parameter_by_name(parameter_name)
            .await?;

        if parameter.is_none() {
            context
                .octopus_database
                .insert_parameter(transaction, parameter_name, "default")
                .await?;
        }
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use crate::{api, api::setup::SetupInfoResponse, app, context::Context, entity::User};
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
        Router,
    };
    use fake::{
        faker::{
            internet::en::SafeEmail,
            lorem::en::{Paragraph, Word},
        },
        Fake,
    };
    use http_body_util::BodyExt;
    use sqlx::{Postgres, Transaction};
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    pub fn get_setup_post_params() -> (String, String, String) {
        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = format!("password123{}", Word().fake::<String>());

        (company_name, email, password)
    }

    pub async fn setup_cleanup(
        context: Arc<Context>,
        transaction: &mut Transaction<'_, Postgres>,
        company_ids: &[Uuid],
        user_ids: &[Uuid],
    ) {
        let _ = context
            .octopus_database
            .try_delete_user_by_ids(transaction, user_ids)
            .await;

        let _ = context
            .octopus_database
            .try_delete_company_by_ids(transaction, company_ids)
            .await;
    }

    pub async fn setup_post(
        router: Router,
        company_name: &str,
        email: &str,
        password: &str,
    ) -> User {
        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        body
    }

    #[tokio::test]
    async fn info_200() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let (company_name, email, password) = get_setup_post_params();
        let user = setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        let body: SetupInfoResponse = serde_json::from_slice(&body).unwrap();

        assert!(!body.setup_required);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn register_201() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = get_setup_post_params();
        let user = setup_post(router, &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }

    #[tokio::test]
    async fn register_400() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = get_setup_post_params();
        let repeat_password = "password1234";

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &repeat_password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_409() {
        let app = app::tests::get_test_app().await;
        let router = app.router;

        let (company_name, email, password) = get_setup_post_params();
        let user = setup_post(router.clone(), &company_name, &email, &password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let response = router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/v1/setup")
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(
                        serde_json::json!({
                            "company_name": &company_name,
                            "email": &email,
                            "password": &password,
                            "repeat_password": &password,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        setup_cleanup(
            app.context.clone(),
            &mut transaction,
            &[company_id],
            &[user_id],
        )
        .await;

        api::tests::transaction_commit(app.context.clone(), transaction).await;
    }
}

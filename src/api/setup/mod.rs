use crate::{
    api::auth,
    context::Context,
    entity::{WorkspacesType, ROLE_COMPANY_ADMIN_USER, ROLE_PRIVATE_USER, ROLE_PUBLIC_USER},
    error::AppError,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct SetupInfoResponse {
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

    let setup_info_response = SetupInfoResponse {
        setup_required: companies.is_empty(),
    };

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

    let user_exists = context
        .octopus_database
        .try_get_user_by_email(&input.email)
        .await?;

    match user_exists {
        None => {
            if input.password != input.repeat_password {
                return Err(AppError::PasswordDoesNotMatch);
            }

            let cloned_context = context.clone();
            let cloned_password = input.password.clone();
            let pw_hash = tokio::task::spawn_blocking(move || {
                auth::hash_password(cloned_context, cloned_password)
            })
            .await??;

            let mut transaction = context.octopus_database.transaction_begin().await?;

            let company = context
                .octopus_database
                .insert_company(&mut transaction, None, &input.company_name)
                .await?;

            let user = context
                .octopus_database
                .insert_user(
                    &mut transaction,
                    company.id,
                    &input.email,
                    true,
                    false,
                    context.config.pepper_id,
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

            let example_prompts = context.octopus_database.get_example_prompts().await?;

            if example_prompts.is_empty() {
                let example_prompt_categories = vec![
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
                ];

                for example_prompt_category_tmp in example_prompt_categories {
                    let example_prompt_category = context
                        .octopus_database
                        .insert_example_prompt_category(
                            &mut transaction,
                            &example_prompt_category_tmp.description,
                            true,
                            &example_prompt_category_tmp.title,
                        )
                        .await?;

                    for example_prompt_tmp in example_prompt_category_tmp.prompts {
                        context
                            .octopus_database
                            .insert_example_prompt(
                                &mut transaction,
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

            context
                .octopus_database
                .transaction_commit(transaction)
                .await?;

            Ok((StatusCode::CREATED, Json(user)).into_response())
        }
        Some(_user_exists) => Err(AppError::UserAlreadyExists),
    }
}

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

#[cfg(test)]
pub mod tests {
    use crate::{api::setup::SetupInfoResponse, app, entity::User, Args};
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
    use tower::ServiceExt;

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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: User = serde_json::from_slice(&body).unwrap();

        assert_eq!(body.email, email);

        body
    }

    #[tokio::test]
    async fn info_200() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
            test_mode: Some(true),
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let second_router = router.clone();
        let third_router = router.clone();

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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SetupInfoResponse = serde_json::from_slice(&body).unwrap();

        assert!(!body.setup_required || body.setup_required);

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = setup_post(second_router, &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let response = third_router
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

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: SetupInfoResponse = serde_json::from_slice(&body).unwrap();

        assert!(!body.setup_required);

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn register_201() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
            test_mode: Some(true),
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = setup_post(router, &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let mut transaction = app
            .context
            .octopus_database
            .transaction_begin()
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn register_400() {
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
            test_mode: Some(true),
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";
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
        let args = Args {
            azure_openai_api_key: None,
            azure_openai_deployment_id: None,
            azure_openai_enabled: Some(true),
            database_url: Some(String::from(
                "postgres://admin:admin@db/octopus_server_test",
            )),
            openai_api_key: None,
            port: None,
            test_mode: Some(true),
        };
        let app = app::get_app(args).await.unwrap();
        let router = app.router;
        let cloned_router = router.clone();

        let company_name = Paragraph(1..2).fake::<String>();
        let email = format!(
            "{}{}{}",
            Word().fake::<String>(),
            Word().fake::<String>(),
            SafeEmail().fake::<String>()
        );
        let password = "password123";

        let user = setup_post(router, &company_name, &email, password).await;
        let company_id = user.company_id;
        let user_id = user.id;

        let response = cloned_router
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

        app.context
            .octopus_database
            .try_delete_user_by_id(&mut transaction, user_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .try_delete_company_by_id(&mut transaction, company_id)
            .await
            .unwrap();

        app.context
            .octopus_database
            .transaction_commit(transaction)
            .await
            .unwrap();
    }
}

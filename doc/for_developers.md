# Running manually (for developers)

Octopus Server is built with [Rust language](https://www.rust-lang.org/). To run it manually, you need to have Rust [installed](https://www.rust-lang.org/tools/install) on your system.

Different parts of Octopus Server have different requirements:
- [PostgreSQL](https://www.postgresql.org/) is required.
- Process manager uses Linux kernel control groups for isolation purposes, so you need to run a server with root privileges if you want to run Octopus AI Services and Octopus WASP Applications on your local system.
- Python [Miniconda](https://docs.anaconda.com/miniconda/) environment is required for running Octopus AI Services.
- A Nvidia card with configured proprietary drivers is required for running some of Octopus AI Services.
- [Node](https://nodejs.org/en) environment is required for running Octopus Client and Octopus WASP Applications.
- [Ollama](https://ollama.com/) environment is required if you want to use Ollama-supported LLMs.
- [Selenium](https://www.selenium.dev/) environment is required if you want to use Octopus AI Services that depend on web scraping features.

Before running Octopus Server manually you need to make sure you have setted up these [environment variables](https://github.com/metric-space-ai/octopus_server/blob/dev/.env).

The configuration may look like the one below.

```text
DATABASE_URL=postgres://admin:admin@db/octopus_server
NEXTCLOUD_SUBDIR=octopus_retrieval/preview/
OCTOPUS_PEPPER=randompepper
OCTOPUS_PEPPER_ID=0
OCTOPUS_SERVER_PORT=8080
OCTOPUS_WS_SERVER_PORT=8081
OLLAMA_HOST=http://localhost:11434
OPENAI_API_KEY=some_api_key
SENDGRID_API_KEY=some_api_key
WASP_DATABASE_URL=postgres://admin:admin@db
WEB_DRIVER_URL=http://localhost:4444
```

You also need to have a working PostgreSQL database. Before using the software you need to migrate the database structure to the proper version. You can do this using [sqlx tool](https://github.com/launchbadge/sqlx). You can install it by running the command:

```sh
cargo install sqlx-cli
```

Using this tool, you can create and migrate a database.

```sh
sqlx database create
sqlx migrate run
Applied 20230630073639/migrate initial (34.650427ms)
Applied 20230913072315/migrate v0.2 alter chat messages (1.907569ms)
[..]
Applied 20241010085533/migrate v0.10 alter chat messages (3.282136ms)
Applied 20241125112925/migrate v0.10 create table tasks (15.058293ms)
```

When you have configured environment variables and database you may try to start Octopus Server.

```sh
cargo run
   Compiling proc-macro2 v1.0.93
   Compiling unicode-ident v1.0.14
[..]
   Compiling sqlx v0.8.3
   Compiling octopus_server v0.10.10 (/home/michal/projects/project_octopus/octopus_server)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 21s
     Running `target/debug/octopus_server`
```

You can find Octopus Server logs in octopus_server.log file.

You can build an optimized, production version of Octopus Server by running the command.

```sh
cargo build --release
   Compiling proc-macro2 v1.0.93
   Compiling unicode-ident v1.0.14
[..]
   Compiling sqlx v0.8.3
   Compiling octopus_server v0.10.10 (/home/michal/projects/project_octopus/octopus_server)
    Finished `release` profile [optimized] target(s) in 5m 00s
```

When you have a running server, you can check API documentation by visiting

```text
http://localhost:8080/swagger-ui/
```

If you have set up the [Octopus Client](https://github.com/metric-space-ai/octopus_client) application, you can now try to connect to the Octopus Server. This step should populate the parameters table in the database. If you want to make it from the API level, you can send a GET request to the endpoint

```text
http://localhost:8080/api/v1/setup
```

After setting up an Octopus Client connection to an Octopus Server, you must register an administrator account. Next, you need to log in with administrator credentials and then go to Settings->Parameters section, and set up basic parameters that will allow you to communicate with third-party LLMs.

```text
MAIN_LLM=openai
MAIN_LLM_OPENAI_API_KEY=api_key
MAIN_LLM_OPENAI_PRIMARY_MODEL=gpt-4o-mini-2024-07-18
MAIN_LLM_OPENAI_SECONDARY_MODEL=gpt-4o-2024-08-06
```

Useful development commands.

Format command makes sure that the code is properly formatted according to Rust language standards and best practices.

```sh
cargo fmt
```

The clippy command makes sure that the code follows the best practices of idiomatic Rust.

```sh
cargo clippy
   Compiling proc-macro2 v1.0.93
   Compiling unicode-ident v1.0.14
[..]
    Checking sqlx v0.8.3
    Checking octopus_server v0.10.10 (/home/michal/projects/project_octopus/octopus_server)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 22s
```

The sqlx prepare command makes sure that you have properly generated metadata files for checking SQL queries.

```sh
cargo sqlx prepare
   Compiling proc-macro2 v1.0.93
   Compiling unicode-ident v1.0.14
[..]
    Checking octopus_server v0.10.10 (/home/michal/projects/project_octopus/octopus_server)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 01s
query data written to .sqlx in the current directory; please check this into version control
```

Test command makes sure that changes didn't broke existing interfaces.

```sh
cargo test
   Compiling cfg-if v1.0.0
   Compiling libc v0.2.169
[..]
   Compiling sqlx v0.8.3
   Compiling octopus_server v0.10.10 (/home/michal/projects/project_octopus/octopus_server)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 3m 40s
     Running unittests src/lib.rs (target/debug/deps/octopus_server-cb0be6087dd147dd)

running 861 tests
test api::ai_functions::tests::delete_401 ... ok
test api::ai_functions::tests::delete_403_deleted_user ... ok
[..]
test api::workspaces::tests::update_404 ... ok
test api::workspaces::tests::update_403_private ... ok

test result: ok. 861 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 668.67s

     Running unittests src/main.rs (target/debug/deps/octopus_server-fb187e04b85baa1e)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests octopus_server

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Octopus Server has a large set of functional tests that cover a large part of server API. Unfortunately, these tests are not complete enough to make any guarantee that the change didn't break server functionality. In future releases, we will try to provide more extensive set of both functional and unit tests.

If you have problem with running the Octopus Server in your environment, please have a look at this [Dockerfile](https://github.com/metric-space-ai/octopus_server/blob/dev/Dockerfile). It's used to provide production container builds. It contains all instructions needed to prepare a fully functional Octopus Server container.

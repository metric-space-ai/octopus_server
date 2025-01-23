# Short PostgreSQL installation guide

You need to make sure that information about packages in the system is updated.

```sh
sudo apt-get update
```

You need to install the GPG key.

```sh
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg
```

And configure an additional package repository.

```sh
sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
```

Now you need to update information about packages from the newly added repository.

```sh
sudo apt-get update
```

You can install the PostgreSQL database now.

```sh
sudo apt-get install postgresql-17
```

You need to start PostgreSQL and enable it on the system boot.

```sh
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

The configuration below allows you to log into the database from different hosts.

```sh
sudo sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/g" /etc/postgresql/17/main/postgresql.conf
```

```sh
sudo echo "host    all             all             0.0.0.0/0            scram-sha-256" >> /etc/postgresql/17/main/pg_hba.conf
```

You need to restart the server to apply it.

```sh
sudo systemctl restart postgresql
```

You can open the PostgreSQL port on the firewall.

```sh
sudo ufw allow 5432/tcp
```

You can log in to PostgreSQL.

```sh
sudo -u postgres psql
```

Now you can change the password for the "postgres" user.

```text
ALTER USER postgres PASSWORD 'somepassword';
```

You can use new credentials to log in to PostgreSQL.

```sh
psql -U postgres -W -h localhost
```

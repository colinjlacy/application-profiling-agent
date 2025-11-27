# Some Notes
- in a running Ubuntu container, have to `apt install postgresql` for the `libpg.so.5` file to show up in `/usr/lib/aarch64-gnu-linux/`
- this means the most likely approach to working prototype is a Ubuntu with all the things
- it's weird that my Ubuntu image didn't have Python nor PostgreSQL installed:
- run the following to set up postgres, assuming root:
```sh
apt update
apt install python3
apt install pip
apt install postgres
apt install postgresql-client
mkdir -p /var/run/postgresql
chmod 777 /var/run/postgresql/
adduser colin
su colin
export PATH=/usr/lib/postgresql/14/bin:$PATH
initdb -D ~/pg/data
pg_ctl -D ~/pg/data start
psql template1
```
  - then create the DB and user:
```sql
CREATE DATABASE test;
CREATE USER test WITH PASSWORD 'test';
GRANT ALL PRIVILEGES ON DATABASE test TO test;
```
  - sign in as the test user:
```shell
psql -U test
```
  - and then create a demo table:
```shell
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL
);
```


# 1) Build the Go test app image
cd testapp
docker build -t go-testapp:latest .

cd ..

# 2) Build the eBPF agent image
cd agent
docker build -t libpq-agent:latest .

cd ..

e9760072d6f3

docker run --rm --name libpq-agent \
--privileged \
--pid=host \
-v /proc:/proc:ro \
-v "$(pwd)/out:/output" \
-e TARGET_PATTERN=testapp \
-e OUTPUT_FILE=/output/pqexec.log \
libpq-ebpf-agent-go:latest
Sponsor Cat
===========
This application will store cat sponsorship information.

Environment variables
--------------------
`DATABASE_URL` _(required)_ - postgres connection string
`POSTGRES_PASSWORD` _(optional)_ - default postgres user password
`SECRET_KEY` _(required)_ - flask secret key for session

Dependencies
------------
Start a postgres container, and load in the schema:
```
$ docker-compose up -d
$ psql -h localhost -p $port -f 000_base.sql
```

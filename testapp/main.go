package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

func main() {
	println("Starting testapp")
	dsn := "host=postgres user=postgres password=postgres dbname=postgres sslmode=disable"
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	// Wait for Postgres to be ready
	for {
		if err := db.Ping(); err != nil {
			log.Printf("waiting for postgres: %v", err)
			time.Sleep(time.Second)
			continue
		}
		break
	}
	log.Println("connected to postgres")

	// Ensure table exists
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users(
		id   SERIAL PRIMARY KEY,
		name TEXT
	)`)
	if err != nil {
		log.Fatalf("create table: %v", err)
	}

	// Insert a sample row
	_, err = db.Exec(`INSERT INTO users(name) VALUES($1)`, "alice")
	if err != nil {
		log.Printf("insert user: %v", err)
	}

	for {
		// This SELECT * should trigger PQexec inside libpq
		rows, err := db.Query(`SELECT * FROM users`)
		if err != nil {
			log.Fatalf("select users: %v", err)
		}
		defer rows.Close()

		log.Println("rows from users table:")
		for rows.Next() {
			var id int
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				log.Fatalf("scan row: %v", err)
			}
			fmt.Printf("user: id=%d name=%s\n", id, name)
		}

		// Keep the process alive for a bit so the agent can see activity
		log.Println("sleeping for 5s so the agent can profile libpq...")
		time.Sleep(5 * time.Second)
	}
}

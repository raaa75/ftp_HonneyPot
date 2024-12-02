package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite" // SQLite driver
)

func main() {
	// Initialize logger
	logFile, err := os.OpenFile("honeypot.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	// Initialize SQLite database
	db, err := sql.Open("sqlite", "file:honeypot.db?cache=shared&mode=rwc")
	if err != nil {
		log.Fatal(err) // Log the error and exit
	}
	defer db.Close()

	// Create table if it doesn't exist
	createTables(db)

	// Ports to monitor
	ports := []string{":21", ":80"} // Example ports (include 21 for FTP)

	var wg sync.WaitGroup
	wg.Add(len(ports))

	// Start a goroutine for each port
	for _, port := range ports {
		go func(port string) {
			defer wg.Done()
			listenOnPort(port, db)
		}(port)
	}

	wg.Wait()
}

func listenOnPort(port string, db *sql.DB) {
	listener, err := net.Listen("tcp", port)
	if err != nil {
		log.Printf("Error listening on port %s: %v\n", port, err)
		return
	}
	defer listener.Close()
	log.Printf("Honeypot listening on port %s...\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}
		go handleConnection(conn, db)
	}
}

func handleConnection(conn net.Conn, db *sql.DB) {
	defer conn.Close()

	// Get source IP
	sourceIP := conn.RemoteAddr().String()

	// Log connection attempt
	logEvent(db, sourceIP, "Connection attempt")

	// Send a fake FTP banner
	fmt.Fprintln(conn, "220 Welcome to the honeypot server")

	// Read commands and log them
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			logEvent(db, sourceIP, "Connection closed")
			break
		}
		command := string(buf[:n])
		logEvent(db, sourceIP, command)

		// Simple command handling (optional)
		if command == "USER anonymous\r\n" {
			fmt.Fprintln(conn, "331 Please specify the password.")
		} else if command == "PASS password\r\n" {
			fmt.Fprintln(conn, "230 Login successful.")
		} else {
			fmt.Fprintln(conn, "500 Unknown command.")
		}
	}
}

func logEvent(db *sql.DB, sourceIP string, command string) {
	stmt, err := db.Prepare("INSERT INTO events(timestamp, source_ip, command) values(?, ?, ?)")
	if err != nil {
		log.Println("Error preparing statement:", err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(time.Now(), sourceIP, command)
	if err != nil {
		log.Println("Error logging event:", err)
	}
}

func createTables(db *sql.DB) {
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            source_ip TEXT NOT NULL,
            command TEXT NOT NULL
        )
    `)
	if err != nil {
		log.Fatal(err) // Log the error and exit
	}
}

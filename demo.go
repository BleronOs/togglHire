package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
}

type Claims struct {
	jwt.StandardClaims
	ID       int    `json:"id"`
	Username string `json:"username"`
}

type Signature struct {
	UserID    int       `json:"user_id"`
	Signature string    `json:"signature"`
	Questions []string  `json:"questions"`
	Answers   []string  `json:"answers"`
	Timestamp time.Time `json:"timestamp"`
}

type TestSignerService struct {
	db *pgxpool.Pool
	mu sync.RWMutex
}

func NewTestSignerService(databaseURL string) (*TestSignerService, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	db, err := pgxpool.ConnectConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the database: %v", err)
	}

	return &TestSignerService{db: db, mu: sync.RWMutex{}}, nil
}

func AuthenticateUser(db *pgxpool.Pool, username, password string) (string, error) {
	var storedPassword string
	var userID int

	err := db.QueryRow(context.TODO(), `
		SELECT id, password FROM users WHERE username = $1
	`, username).Scan(&userID, &storedPassword)
	if err != nil {
		return "", fmt.Errorf("authentication failed: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		return "", fmt.Errorf("authentication failed: %v", err)
	}

	token, err := generateJWTToken(username, userID)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT token: %v", err)
	}

	return token, nil
}

// RegisterUser creates a new user account
func RegisterUser(db *pgxpool.Pool, username, password string) error {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}
	_, err = db.Exec(context.TODO(), `
		INSERT INTO users (username, password) VALUES ($1, $2)
	`, username, hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to register user: %v", err)
	}

	return nil
}

func generateJWTToken(username string, userID int) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
		},
		ID:       userID,
		Username: username,
	})

	signedToken, err := token.SignedString([]byte("your-secret-key"))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %v", err)
	}

	return signedToken, nil
}

func isValidToken(r *http.Request) bool {

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}

	if len(authHeader) > 7 && strings.ToUpper(authHeader[0:7]) == "BEARER " {
		authHeader = authHeader[7:]
	} else {
		return false
	}

	token, err := jwt.ParseWithClaims(authHeader, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil
	})
	if err != nil || !token.Valid {
		return false
	}

	return true
}

func TokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if !isValidToken(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *TestSignerService) SignHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		http.Error(w, "Database connection is nil", http.StatusInternalServerError)
		return
	}

	if !isValidToken(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	userID := vars["userID"]

	var requestBody struct {
		Questions []string `json:"questions"`
		Answers   []string `json:"answers"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	signature := fmt.Sprintf("example-signature-for-%s", userID)

	_, err = s.db.Exec(r.Context(), `
		INSERT INTO signatures (user_id, signature, questions ,answers, timestamp)
		VALUES ($1, $2, $3, $4, $5)
	`, userID, signature, pq.Array(requestBody.Questions), pq.Array(requestBody.Answers), time.Now())

	if err != nil {
		http.Error(w, "Failed to save signature to the database", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"test-signature": signature})
}

func (s *TestSignerService) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.db == nil {
		http.Error(w, "Database connection is nil", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	userID := vars["userID"]
	signature := vars["signature"]

	var storedSignature Signature

	err := s.db.QueryRow(r.Context(), `
	select
		user_id,
		signature,
		answers,
		timestamp
    from
		signatures
    where
		user_id = $1
	and signature = $2
	`, userID, signature).Scan(
		&storedSignature.UserID,
		&storedSignature.Signature,
		pq.Array(&storedSignature.Answers),
		&storedSignature.Timestamp,
	)

	if err == sql.ErrNoRows {
		http.Error(w, "Signature not found or does not match", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, fmt.Sprintf("Error retrieving signature from the database: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "OK",
		"user_id":   storedSignature.UserID,
		"answers":   storedSignature.Answers,
		"timestamp": storedSignature.Timestamp,
		"signature": storedSignature.Signature,
	})
}

func LoginHandler(service *TestSignerService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		err := json.NewDecoder(r.Body).Decode(&requestBody)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		token, err := AuthenticateUser(service.db, requestBody.Username, requestBody.Password)
		if err != nil {
			http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}

func RegisterHandler(service *TestSignerService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		err := json.NewDecoder(r.Body).Decode(&requestBody)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		err = RegisterUser(service.db, requestBody.Username, requestBody.Password)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to register user: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
	}
}

func (s *TestSignerService) CreateTables() error {
	_, err := s.db.Exec(context.TODO(), `
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL
        );

        CREATE TABLE IF NOT EXISTS signatures (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) NOT NULL,
            signature VARCHAR(255) NOT NULL,
			questions VARCHAR(255)[] NOT NULL,
            answers VARCHAR(255)[] NOT NULL,
            timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_signatures_user_signature ON signatures (user_id, signature);
    `)

	return err
}

func main() {
	connectionString := "user=postgres password=S!gnatur3.!213. host=db.htwyongmdmmwxwgvlhga.supabase.co port=5432 dbname=postgres"

	service, err := NewTestSignerService(connectionString)
	if err != nil {
		log.Fatal("Failed to initialize TestSignerService:", err)
	}

	if err := service.CreateTables(); err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	router := mux.NewRouter()

	router.Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.WriteHeader(http.StatusNoContent)
	})

	router.Handle("/sign/{userID}", TokenMiddleware(http.HandlerFunc(service.SignHandler))).Methods("POST")
	router.Handle("/verify/{userID}/{signature}", TokenMiddleware(http.HandlerFunc(service.VerifyHandler))).Methods("GET")

	router.HandleFunc("/register", RegisterHandler(service)).Methods("POST")
	router.HandleFunc("/login", LoginHandler(service)).Methods("POST")

	log.Println("Server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

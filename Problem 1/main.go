package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Session struct {
	SID string `json:"sid"`
}

type Note struct {
	SID  string `jsom:"sid"`
	ID   uint32 `json:"id,omitempty"`
	Note string `json:"note,omitempty"`
}
type SendNote struct {
	ID   uint32 `json:"id"`
	Note string `json:"note"`
}

type JSONResponse struct {
	Error   bool        `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
	Note    interface{} `json:"notes,omitempty"`
}

var users []User
var notes map[string][]Note
var noteIDCounter uint32 = 1
var userIDCounter uint32 // Counter for generating unique user IDs

func main() {

	router := mux.NewRouter()

	notes = make(map[string][]Note)

	router.HandleFunc("/signup", CreateUser).Methods("POST")
	router.HandleFunc("/login", Login).Methods("POST")
	router.HandleFunc("/notes", GetNote).Methods("GET")
	router.HandleFunc("/notes", CreateNote).Methods("POST")
	router.HandleFunc("/notes", DeleteNote).Methods("DELETE")

	fmt.Println("Server is running on port 8080")
	http.ListenAndServe(":8080", router)
}
func CreateUser(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if user.Name == "" || user.Email == "" || user.Password == "" {
		http.Error(w, "Bad Request name or user name or password must not be empty", http.StatusBadRequest)
		return
	}
	userIDCounter++
	// Generate a unique user ID
	user.ID = strconv.Itoa(int(userIDCounter))

	// Append the user to the users slice
	users = append(users, user)

	w.WriteHeader(http.StatusOK)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var inputUser User
	if err := json.NewDecoder(r.Body).Decode(&inputUser); err != nil {
		http.Error(w, "Bad Request: Invalid request format", http.StatusBadRequest)
		return
	}

	if inputUser.Email == "" || inputUser.Password == "" {
		http.Error(w, "Bad Request: Username or password must not be empty", http.StatusBadRequest)
		return
	}

	for _, user := range users {
		if user.Email == inputUser.Email && user.Password == inputUser.Password {
			userID := user.ID // Replace with the actual user ID
			token, err := generateJWT(userID)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Create a login response
			response := Session{SID: token}

			// Encode and send the response as JSON
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
			return
		}
	}

	// Create a login response for unauthorized access
	response := JSONResponse{Message: "Unauthorized: Email or password is incorrect"}
	WriteJSON(w, http.StatusUnauthorized, response)

}

func CreateNote(w http.ResponseWriter, r *http.Request) {
	// Retrieve the JWT token from the Authorization header
	var requestNote Note

	err := ReadJSON(w, r, &requestNote)
	if err != nil {
		ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	// Verify and decode the JWT token
	userID, err := verifyJWT(requestNote.SID)
	if err != nil {
		http.Error(w, "Unauthorized: Invalid JWT token", http.StatusUnauthorized)
		return
	}

	// Check if the user session exists
	userNotes, _ := notes[userID]
	requestNote.ID = noteIDCounter
	noteIDCounter++

	userNotes = append(userNotes, requestNote)
	notes[userID] = userNotes

	// Create a response with the newly created note's ID
	response := map[string]uint32{"id": requestNote.ID}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
func GetNote(w http.ResponseWriter, r *http.Request) {
	var requestPayload Session

	err := ReadJSON(w, r, &requestPayload)
	if err != nil {
		ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	// Verify and decode the JWT token
	userID, err := verifyJWT(requestPayload.SID)
	if err != nil {
		http.Error(w, "Unauthorized: Invalid JWT token", http.StatusUnauthorized)
		return
	}

	// Check if the user session exists
	userNotes, exists := notes[userID]
	if !exists {
		http.Error(w, "Unauthorized: Session not found", http.StatusUnauthorized)
		return
	}

	var sendNotes []SendNote
	for _, note := range userNotes {
		sendNote := SendNote{
			ID:   note.ID,
			Note: note.Note,
		}
		sendNotes = append(sendNotes, sendNote)
	}

	resp := JSONResponse{
		Note: sendNotes,
	}

	_ = WriteJSON(w, http.StatusOK, resp)
}
func DeleteNote(w http.ResponseWriter, r *http.Request) {
	var requestPay Note

	err := ReadJSON(w, r, &requestPay)
	if err != nil {
		ErrorJSON(w, err, http.StatusBadRequest)
		return
	}

	// Verify and decode the JWT token
	userID, err := verifyJWT(requestPay.SID)
	if err != nil {
		http.Error(w, "Unauthorized: Invalid JWT token", http.StatusUnauthorized)
		return
	}

	// Check if the user session exists
	userNotes, exists := notes[userID]
	if !exists {
		http.Error(w, "Unauthorized: Session not found", http.StatusUnauthorized)
		return
	}

	// Find and remove the note with the specified ID
	var updatedUserNotes []Note
	found := false
	for _, note := range userNotes {
		if note.ID == requestPay.ID {
			found = true
		} else {
			updatedUserNotes = append(updatedUserNotes, note)
		}
	}

	if !found {
		http.Error(w, "Bad Request: Note not found", http.StatusBadRequest)
		return
	}

	notes[userID] = updatedUserNotes
	w.WriteHeader(http.StatusOK)
}

var jwtSecret = []byte("accuknox")

func generateJWT(userID string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = userID
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expiration time
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func verifyJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID := claims["sub"].(string)
		return userID, nil
	}
	return "", errors.New("Invalid token")
}

func WriteJSON(w http.ResponseWriter, status int, data interface{}, headers ...http.Header) error {
	out, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if len(headers) > 0 {
		for key, value := range headers[0] {
			w.Header()[key] = value
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(out)
	if err != nil {
		return err
	}

	return nil
}

func ReadJSON(w http.ResponseWriter, r *http.Request, data interface{}) error {
	maxBytes := 1024 * 1024 // one megabyte
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))

	dec := json.NewDecoder(r.Body)

	dec.DisallowUnknownFields()

	err := dec.Decode(data)
	if err != nil {
		return err
	}

	err = dec.Decode(&struct{}{})
	if err != io.EOF {
		return errors.New("body must only contain a single JSON value")
	}

	return nil
}

func ErrorJSON(w http.ResponseWriter, err error, status ...int) error {
	statusCode := http.StatusBadRequest

	if len(status) > 0 {
		statusCode = status[0]
	}

	var payload JSONResponse
	payload.Error = true
	payload.Message = err.Error()

	return WriteJSON(w, statusCode, payload)
}

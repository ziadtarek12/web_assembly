package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"syscall/js"
)

// API base URL - replace with actual API URL in production
var apiBaseURL = "https://zeyadomaro.alwaysdata.net/v1"

// Authentication token storage
var authToken string

// User structure for authentication
type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Film structure to match API response
type Film struct {
	ID          int      `json:"id"`
	Title       string   `json:"title"`
	Year        int      `json:"year"`
	Runtime     string   `json:"runtime"`
	Rating      float64  `json:"rating"`
	Description string   `json:"description"`
	Image       string   `json:"image"`
	Version     int      `json:"version"`
	Genres      []string `json:"genres"`
	Directors   []string `json:"directors"`
	Actors      []string `json:"actors"`
}

// Helper function for making HTTP requests
func makeRequest(method, endpoint string, body interface{}, useAuth bool) (map[string]interface{}, error) {
	url := apiBaseURL + endpoint

	var reqBody []byte
	var err error
	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	// Create request
	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add auth token if needed
	if useAuth && authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse response
	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	// Check for API errors
	if resp.StatusCode >= 400 {
		errMsg, ok := result["error"].(string)
		if ok {
			return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, errMsg)
		}
		return nil, fmt.Errorf("API error (%d): Unknown error", resp.StatusCode)
	}

	return result, nil
}

// Register a new user
func registerUser(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return map[string]interface{}{
			"success": false,
			"error":   "Name, email, and password required",
		}
	}

	name := args[0].String()
	email := args[1].String()
	password := args[2].String()

	user := User{
		Name:     name,
		Email:    email,
		Password: password,
	}

	response, err := makeRequest("POST", "/users", user, false)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"data":    response,
	}
}

// Activate a user account
func activateUser(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Activation token required",
		}
	}

	token := args[0].String()

	body := map[string]string{
		"token": token,
	}

	response, err := makeRequest("PUT", "/users/activate", body, false)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"data":    response,
	}
}

// Login and get authentication token
func login(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return map[string]interface{}{
			"success": false,
			"error":   "Email and password required",
		}
	}

	email := args[0].String()
	password := args[1].String()

	body := map[string]string{
		"email":    email,
		"password": password,
	}

	response, err := makeRequest("POST", "/tokens/authentication", body, false)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	// Extract and store the auth token
	authTokenData, ok := response["authentication_token"].(map[string]interface{})
	if !ok {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid authentication response",
		}
	}

	token, ok := authTokenData["token"].(string)
	if !ok {
		return map[string]interface{}{
			"success": false,
			"error":   "Invalid token format",
		}
	}

	// Store token for future requests
	authToken = token

	return map[string]interface{}{
		"success": true,
		"data":    response,
	}
}

// Get list of films with optional filters
func getFilms(this js.Value, args []js.Value) interface{} {
	// Build query parameters
	queryParams := []string{}

	// Process filters if provided
	if len(args) >= 1 && !args[0].IsUndefined() && !args[0].IsNull() {
		filters := args[0]

		if page := filters.Get("page"); !page.IsUndefined() {
			queryParams = append(queryParams, fmt.Sprintf("page=%s", page.String()))
		}

		if pageSize := filters.Get("page_size"); !pageSize.IsUndefined() {
			queryParams = append(queryParams, fmt.Sprintf("page_size=%s", pageSize.String()))
		}

		if title := filters.Get("title"); !title.IsUndefined() {
			queryParams = append(queryParams, fmt.Sprintf("title=%s", title.String()))
		}

		if genres := filters.Get("genres"); !genres.IsUndefined() {
			queryParams = append(queryParams, fmt.Sprintf("genres=%s", genres.String()))
		}

		if directors := filters.Get("directors"); !directors.IsUndefined() {
			queryParams = append(queryParams, fmt.Sprintf("directors=%s", directors.String()))
		}

		if actors := filters.Get("actors"); !actors.IsUndefined() {
			queryParams = append(queryParams, fmt.Sprintf("actors=%s", actors.String()))
		}

		if sort := filters.Get("sort"); !sort.IsUndefined() {
			queryParams = append(queryParams, fmt.Sprintf("sort=%s", sort.String()))
		}
	}

	// Build URL with query params
	endpoint := "/films"
	if len(queryParams) > 0 {
		endpoint += "?" + strings.Join(queryParams, "&")
	}

	response, err := makeRequest("GET", endpoint, nil, true)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"data":    response,
	}
}

// Get a single film by ID
func getFilmByID(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Film ID required",
		}
	}

	filmID := args[0].String()
	endpoint := fmt.Sprintf("/films/%s", filmID)

	response, err := makeRequest("GET", endpoint, nil, true)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"data":    response,
	}
}

// Create a new film
func createFilm(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 || args[0].Type() != js.TypeObject {
		return map[string]interface{}{
			"success": false,
			"error":   "Film data object required",
		}
	}

	// Extract film data from JavaScript object
	filmObj := args[0]
	film := map[string]interface{}{
		"title":       filmObj.Get("title").String(),
		"year":        filmObj.Get("year").Int(),
		"runtime":     filmObj.Get("runtime").Int(),
		"rating":      filmObj.Get("rating").Float(),
		"description": filmObj.Get("description").String(),
		"image":       filmObj.Get("image").String(),
	}

	// Handle array properties
	genres := []string{}
	genresObj := filmObj.Get("genres")
	genresLen := genresObj.Length()
	for i := 0; i < genresLen; i++ {
		genres = append(genres, genresObj.Index(i).String())
	}
	film["genres"] = genres

	directors := []string{}
	directorsObj := filmObj.Get("directors")
	directorsLen := directorsObj.Length()
	for i := 0; i < directorsLen; i++ {
		directors = append(directors, directorsObj.Index(i).String())
	}
	film["directors"] = directors

	actors := []string{}
	actorsObj := filmObj.Get("actors")
	actorsLen := actorsObj.Length()
	for i := 0; i < actorsLen; i++ {
		actors = append(actors, actorsObj.Index(i).String())
	}
	film["actors"] = actors

	response, err := makeRequest("POST", "/films", film, true)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"data":    response,
	}
}

// Update a film
func updateFilm(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 || args[1].Type() != js.TypeObject {
		return map[string]interface{}{
			"success": false,
			"error":   "Film ID and data object required",
		}
	}

	filmID := args[0].String()
	filmObj := args[1]

	// Extract film data from JavaScript object
	film := map[string]interface{}{
		"title":       filmObj.Get("title").String(),
		"year":        filmObj.Get("year").Int(),
		"runtime":     filmObj.Get("runtime").Int(),
		"rating":      filmObj.Get("rating").Float(),
		"description": filmObj.Get("description").String(),
		"image":       filmObj.Get("image").String(),
	}

	// Handle array properties
	genres := []string{}
	genresObj := filmObj.Get("genres")
	genresLen := genresObj.Length()
	for i := 0; i < genresLen; i++ {
		genres = append(genres, genresObj.Index(i).String())
	}
	film["genres"] = genres

	directors := []string{}
	directorsObj := filmObj.Get("directors")
	directorsLen := directorsObj.Length()
	for i := 0; i < directorsLen; i++ {
		directors = append(directors, directorsObj.Index(i).String())
	}
	film["directors"] = directors

	actors := []string{}
	actorsObj := filmObj.Get("actors")
	actorsLen := actorsObj.Length()
	for i := 0; i < actorsLen; i++ {
		actors = append(actors, actorsObj.Index(i).String())
	}
	film["actors"] = actors

	endpoint := fmt.Sprintf("/films/%s", filmID)
	response, err := makeRequest("PATCH", endpoint, film, true)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"data":    response,
	}
}

// Delete a film
func deleteFilm(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Film ID required",
		}
	}

	filmID := args[0].String()
	endpoint := fmt.Sprintf("/films/%s", filmID)

	response, err := makeRequest("DELETE", endpoint, nil, true)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
		"data":    response,
	}
}

// Check if user is authenticated
func isAuthenticated(this js.Value, args []js.Value) interface{} {
	return authToken != ""
}

// Logout - clear authentication token
func logout(this js.Value, args []js.Value) interface{} {
	authToken = ""
	return true
}

// Change API base URL (for development/testing)
func setAPIBaseURL(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return false
	}

	apiBaseURL = args[0].String()
	return true
}

func main() {
	// Register JavaScript functions
	js.Global().Set("registerUser", js.FuncOf(registerUser))
	js.Global().Set("activateUser", js.FuncOf(activateUser))
	js.Global().Set("login", js.FuncOf(login))
	js.Global().Set("getFilms", js.FuncOf(getFilms))
	js.Global().Set("getFilmByID", js.FuncOf(getFilmByID))
	js.Global().Set("createFilm", js.FuncOf(createFilm))
	js.Global().Set("updateFilm", js.FuncOf(updateFilm))
	js.Global().Set("deleteFilm", js.FuncOf(deleteFilm))
	js.Global().Set("isAuthenticated", js.FuncOf(isAuthenticated))
	js.Global().Set("logout", js.FuncOf(logout))
	js.Global().Set("setAPIBaseURL", js.FuncOf(setAPIBaseURL))

	// Keep the program running
	select {}
}

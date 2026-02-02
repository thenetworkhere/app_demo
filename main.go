// ====================================================================================
// TON.PLACE MINI APP DEMO
// ====================================================================================
// This is a demonstration application showing how to integrate with Ton.Place platform.
// It covers:
//   1. User authorization via HMAC-SHA256 signature verification
//   2. Fetching user's purchase history via Public API
//   3. Creating new purchases (payment requests)
//   4. Using TonPlace JavaScript SDK for payments and social features
//
// API Base URL: https://api.tonplace.net
// SDK URL: https://ton.place/app_sdk.js
// ====================================================================================

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// ====================================================================================
// CONFIGURATION
// ====================================================================================
// Replace these with your actual App credentials from Ton.Place developer panel.
// You can get them by creating an app at https://ton.place/apps
// ====================================================================================

const (
	// APP_ID - Your application ID from Ton.Place (required)
	// This is a numeric identifier assigned to your app when you create it
	APP_ID = "YOUR_APP_ID"

	// APP_SECRET - Your application secret key from Ton.Place (required, keep it private!)
	// This 32-character string is used to sign and verify requests
	// NEVER expose this on the client side or in public repositories
	APP_SECRET = "YOUR_APP_SECRET"

	// TON_PLACE_API - Base URL for Ton.Place API
	// All API requests should be made to this endpoint
	TON_PLACE_API = "https://api.tonplace.net"

	// SERVER_PORT - Port for this demo server
	SERVER_PORT = ":8080"

	// SIGNATURE_MAX_AGE - Maximum age of signature in seconds (5 minutes)
	// Requests with older timestamps will be rejected to prevent replay attacks
	SIGNATURE_MAX_AGE = 300
)

// ====================================================================================
// DATA STRUCTURES
// ====================================================================================

// UserParams represents the parameters that Ton.Place passes to your app when user opens it.
// These parameters are appended to your app URL as query string.
// Example: https://yourapp.com?app_id=123&user_id=456&ts=1707981234&first_name=John&last_name=Doe&hash=abc...
type UserParams struct {
	// AppID - Your application ID (always present)
	// Used to identify which app the request is for
	AppID string `json:"app_id"`

	// UserID - Unique identifier of the user on Ton.Place (always present)
	// Use this to identify users in your system
	UserID string `json:"user_id"`

	// Timestamp - Unix timestamp when the signature was created (always present)
	// Used to prevent replay attacks - reject requests with old timestamps
	Timestamp string `json:"ts"`

	// FirstName - User's first name (always present, may be empty string)
	// Display name from user's Ton.Place profile
	FirstName string `json:"first_name"`

	// LastName - User's last name (always present, may be empty string)
	// Display name from user's Ton.Place profile
	LastName string `json:"last_name"`

	// Hash - HMAC-SHA256 signature of all parameters (always present)
	// Used to verify that the request came from Ton.Place and wasn't tampered with
	Hash string `json:"hash"`
}

// Transaction represents a purchase record from Ton.Place API.
// This is returned by GET /apps/purchases endpoint.
type Transaction struct {
	// ID - Unique identifier of the transaction
	ID int64 `json:"id"`

	// Amount - Purchase amount in smallest currency unit (cents for EUR, nanotons for TON)
	// For EUR: 1 EUR = 100 (smallest unit)
	// For TON: 1 TON = 1,000,000,000 (smallest unit)
	Amount int64 `json:"amount"`

	// Currency - Currency code: "eur" or "ton"
	// Currently only "eur" is supported for purchases
	Currency string `json:"currency"`

	// UserID - ID of the user who made the purchase
	UserID int64 `json:"user_id"`

	// CreatedAt - Unix timestamp when purchase was created
	CreatedAt int64 `json:"created_at"`

	// Status - Purchase status: "pending" or "paid"
	// "pending" - payment initiated but not completed
	// "paid" - payment successfully completed
	Status string `json:"status"`

	// Title - Purchase description/title (set when creating purchase)
	Title string `json:"title"`
}

// TransactionsResponse represents the API response for GET /apps/purchases
type TransactionsResponse struct {
	Transactions []Transaction `json:"transactions"`
}

// CreatePurchaseRequest represents the request body for creating a new purchase.
// This is sent to POST /apps/purchase/create endpoint.
type CreatePurchaseRequest struct {
	// Amount - Purchase amount in smallest currency unit (required)
	// For EUR: value in cents (e.g., 100 = 1.00 EUR)
	// Must be greater than 0
	Amount int64 `json:"amount"`

	// Currency - Currency code (required)
	// Currently only "eur" is supported
	Currency string `json:"currency"`

	// Title - Short description of what user is paying for (required)
	// Maximum 150 characters
	// Shown to user in payment dialog
	Title string `json:"title"`

	// UserID - ID of the user who should pay (required)
	// Must match a valid Ton.Place user ID
	UserID int64 `json:"user_id"`
}

// CreatePurchaseResponse represents the API response for POST /apps/purchase/create
type CreatePurchaseResponse struct {
	// PurchaseID - Unique identifier of the created purchase
	// Use this ID with TonPlace.purchase() SDK method to initiate payment
	PurchaseID int64 `json:"purchase_id"`
}

// PageData contains all data passed to the HTML template
type PageData struct {
	User         UserParams
	Transactions []Transaction
	Error        string
	IsAuthorized bool
}

// ====================================================================================
// SIGNATURE VERIFICATION
// ====================================================================================
// This is the most critical security function. It verifies that the request
// actually came from Ton.Place and wasn't forged by an attacker.
//
// The algorithm works as follows:
// 1. Get ALL query parameters from the request (except "hash")
// 2. Sort them alphabetically by key
// 3. Join them with newlines in format: "key1=value1\nkey2=value2"
// 4. Create SHA256 hash of your app secret
// 5. Use that hash as key for HMAC-SHA256 of the joined string
// 6. Compare the result with the provided hash
//
// IMPORTANT: Do NOT hardcode the list of parameters!
// Ton.Place may send different sets of parameters (e.g., with or without first_name/last_name).
// Always use whatever parameters are actually present in the request.
// ====================================================================================

// VerifySignatureFromQuery validates the HMAC-SHA256 signature using all query parameters.
// It dynamically takes all parameters from the request, not a hardcoded list.
// Returns true if signature is valid, false otherwise.
func VerifySignatureFromQuery(queryParams map[string][]string, secret string) bool {
	// Step 1: Collect all parameters except "hash" into a map
	// Take the first value for each parameter (standard behavior for query strings)
	paramsMap := make(map[string]string)
	for key, values := range queryParams {
		if key == "hash" {
			continue // Skip the hash itself
		}
		if len(values) > 0 {
			paramsMap[key] = values[0]
		}
	}

	// Step 2: Get sorted list of keys
	// IMPORTANT: Keys must be sorted alphabetically for consistent signature
	keys := make([]string, 0, len(paramsMap))
	for key := range paramsMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Step 3: Build the check string
	// Format: "key1=value1\nkey2=value2\nkey3=value3"
	// The order must be exactly as sorted above
	var checkStr string
	for i, key := range keys {
		if i > 0 {
			checkStr += "\n"
		}
		checkStr += key + "=" + paramsMap[key]
	}

	// Debug: uncomment to see what string is being signed
	// log.Printf("Check string: %q", checkStr)

	// Step 4: Hash the app secret with SHA256
	// This creates a fixed-size key for HMAC
	secretHasher := sha256.New()
	secretHasher.Write([]byte(secret))
	secretKey := secretHasher.Sum(nil)

	// Step 5: Create HMAC-SHA256 of the check string using hashed secret
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(checkStr))
	expectedHash := hex.EncodeToString(h.Sum(nil))

	// Step 6: Get the provided hash from query params
	providedHash := ""
	if hashValues, ok := queryParams["hash"]; ok && len(hashValues) > 0 {
		providedHash = hashValues[0]
	}

	// Step 7: Compare hashes using constant-time comparison to prevent timing attacks
	return hmac.Equal([]byte(expectedHash), []byte(providedHash))
}

// ValidateTimestamp checks if the signature timestamp is not too old.
// This prevents replay attacks where an attacker captures a valid request and resends it later.
func ValidateTimestamp(tsStr string) bool {
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	age := now - ts

	// Reject if timestamp is in the future (clock skew tolerance: 60 seconds)
	if age < -60 {
		return false
	}

	// Reject if timestamp is too old
	if age > SIGNATURE_MAX_AGE {
		return false
	}

	return true
}

// ====================================================================================
// TON.PLACE API CLIENT FUNCTIONS
// ====================================================================================

// GetTransactions fetches the list of transactions (purchases) for your app.
//
// API Endpoint: GET /apps/purchases
//
// Headers (required):
//   - App-Id: Your application ID
//   - Secret: Your application secret
//
// Query Parameters (all optional):
//   - count: Number of transactions to return (default: 20, max: 100)
//   - last_id: Last transaction ID for pagination (default: 0)
//   - status: Filter by status - "pending" or "paid" (optional, returns all if not specified)
//   - userId: Filter by user ID (optional)
//
// Returns: List of transactions or error
func GetTransactions(appID, secret string, userID int64) ([]Transaction, error) {
	// Build URL with query parameters
	url := fmt.Sprintf("%s/apps/purchases?count=50&userId=%d", TON_PLACE_API, userID)

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set required authentication headers
	// These headers authenticate your app with Ton.Place API
	req.Header.Set("App-Id", appID)  // Your app ID
	req.Header.Set("Secret", secret) // Your app secret (keep it private!)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse JSON response
	var result TransactionsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result.Transactions, nil
}

// CreatePurchase creates a new purchase request that user can pay for.
//
// API Endpoint: POST /apps/purchase/create
//
// Headers (required):
//   - App-Id: Your application ID
//   - Secret: Your application secret
//
// Request Body:
//   - amount: Amount in smallest unit (cents for EUR) - required, must be > 0
//   - currency: Currency code - required, must be "eur"
//   - title: Purchase description - required, max 150 characters
//   - user_id: User ID who will pay - required
//
// Returns: Purchase ID that you pass to TonPlace.purchase() SDK method
func CreatePurchase(appID, secret string, userID int64, amount int64, title string) (int64, error) {
	// Prepare request body
	reqBody := CreatePurchaseRequest{
		Amount:   amount,
		Currency: "eur", // Currently only "eur" is supported
		Title:    title,
		UserID:   userID,
	}

	// Serialize to JSON
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", TON_PLACE_API+"/apps/purchase/create", bytes.NewBuffer(jsonBody))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	req.Header.Set("App-Id", appID)
	req.Header.Set("Secret", secret)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var result CreatePurchaseResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}

	return result.PurchaseID, nil
}

// ====================================================================================
// HTTP HANDLERS
// ====================================================================================

// handleIndex is the main page handler.
// It verifies user authorization and displays their data and transaction history.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	// Skip favicon requests
	if r.URL.Path == "/favicon.ico" {
		http.NotFound(w, r)
		return
	}

	// Get all query parameters from the request
	// Ton.Place appends these to your app URL when user opens the app
	queryParams := r.URL.Query()

	// Extract known parameters for display (these are the common ones)
	// But signature verification uses ALL parameters dynamically
	params := UserParams{
		AppID:     queryParams.Get("app_id"),
		UserID:    queryParams.Get("user_id"),
		Timestamp: queryParams.Get("ts"),
		FirstName: queryParams.Get("first_name"), // May be empty if not sent
		LastName:  queryParams.Get("last_name"),  // May be empty if not sent
		Hash:      queryParams.Get("hash"),
	}

	// Prepare page data
	data := PageData{
		User:         params,
		IsAuthorized: false,
	}

	// Check if required parameters are present
	if params.Hash == "" || params.UserID == "" {
		data.Error = "Missing required parameters. This app must be opened from Ton.Place."
		renderPage(w, data)
		return
	}

	// Validate timestamp to prevent replay attacks
	if !ValidateTimestamp(params.Timestamp) {
		data.Error = "Request expired or invalid timestamp. Please refresh the page."
		renderPage(w, data)
		return
	}

	// Verify signature using ALL query parameters (not just the hardcoded ones)
	// This is important because Ton.Place may send different sets of parameters
	if !VerifySignatureFromQuery(queryParams, APP_SECRET) {
		data.Error = "Invalid signature. Request may have been tampered with."
		renderPage(w, data)
		return
	}

	// Authorization successful!
	data.IsAuthorized = true

	// Fetch user's transaction history
	userID, _ := strconv.ParseInt(params.UserID, 10, 64)
	transactions, err := GetTransactions(APP_ID, APP_SECRET, userID)
	if err != nil {
		log.Printf("Failed to fetch transactions: %v", err)
		// Don't fail the page, just show empty transactions
		data.Transactions = []Transaction{}
	} else {
		data.Transactions = transactions
	}

	renderPage(w, data)
}

// handleCreatePurchase handles purchase creation requests from the client.
// Client calls this endpoint, gets purchase_id, then calls TonPlace.purchase(purchase_id)
func handleCreatePurchase(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set JSON response header
	w.Header().Set("Content-Type", "application/json")

	// Parse request body
	var req struct {
		UserID int64  `json:"user_id"`
		Amount int64  `json:"amount"` // Amount in cents
		Title  string `json:"title"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("JSON decode error: %v", err)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body: " + err.Error()})
		return
	}

	// Validate input
	if req.Amount <= 0 {
		json.NewEncoder(w).Encode(map[string]string{"error": "Amount must be greater than 0"})
		return
	}
	if req.Title == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Title is required"})
		return
	}
	if len(req.Title) > 150 {
		json.NewEncoder(w).Encode(map[string]string{"error": "Title must be 150 characters or less"})
		return
	}

	// Create purchase via Ton.Place API
	purchaseID, err := CreatePurchase(APP_ID, APP_SECRET, req.UserID, req.Amount, req.Title)
	if err != nil {
		log.Printf("Failed to create purchase: %v", err)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create purchase: " + err.Error()})
		return
	}

	// Return purchase ID - client will use this with TonPlace.purchase()
	json.NewEncoder(w).Encode(map[string]int64{"purchase_id": purchaseID})
}

// handleGetTransactions returns fresh transaction list for polling
func handleGetTransactions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	userIDStr := r.URL.Query().Get("user_id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid user_id"})
		return
	}

	transactions, err := GetTransactions(APP_ID, APP_SECRET, userID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"transactions": transactions})
}

// renderPage renders the HTML template with given data
func renderPage(w http.ResponseWriter, data PageData) {
	tmpl := template.Must(template.New("page").Funcs(template.FuncMap{
		"formatAmount": func(amount int64, currency string) string {
			// Convert from smallest unit to display format
			if currency == "ton" {
				return fmt.Sprintf("%.2f TON", float64(amount)/1000000000)
			}
			return fmt.Sprintf("%.2f EUR", float64(amount)/100)
		},
		"formatTime": func(ts int64) string {
			return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
		},
	}).Parse(htmlTemplate))

	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// ====================================================================================
// HTML TEMPLATE
// ====================================================================================
// This template demonstrates:
// 1. Loading and using TonPlace SDK
// 2. Making payments with TonPlace.purchase()
// 3. Using social features: shareApp(), createPost()
// 4. Polling for transaction updates
// ====================================================================================

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ton.Place App Demo</title>

    <!-- ============================================================== -->
    <!-- IMPORTANT: Include TonPlace SDK                                -->
    <!-- This script provides TonPlace object for interacting with      -->
    <!-- the Ton.Place platform (payments, sharing, etc.)               -->
    <!-- ============================================================== -->
    <script src="https://ton.place/app_sdk.js"></script>

    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            max-width: 600px;
            margin: 0 auto;
        }
        .card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .card h2 {
            font-size: 18px;
            margin-bottom: 16px;
            color: #333;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }
        .info-row:last-child { border-bottom: none; }
        .label { color: #666; }
        .value { font-weight: 500; }
        .error {
            background: #fee;
            color: #c00;
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 16px;
        }
        .btn {
            background: #007AFF;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
            margin-bottom: 8px;
        }
        .btn:hover { background: #0056b3; }
        .btn:disabled { background: #ccc; cursor: not-allowed; }
        .btn-secondary { background: #6c757d; }
        .btn-secondary:hover { background: #545b62; }
        .transaction {
            padding: 12px;
            border: 1px solid #eee;
            border-radius: 8px;
            margin-bottom: 8px;
        }
        .transaction-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }
        .transaction-title { font-weight: 500; }
        .transaction-amount { color: #28a745; font-weight: 600; }
        .transaction-meta { font-size: 12px; color: #666; }
        .status {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
        }
        .status-pending { background: #fff3cd; color: #856404; }
        .status-paid { background: #d4edda; color: #155724; }
        .code-block {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 12px;
            font-family: monospace;
            font-size: 13px;
            overflow-x: auto;
            margin: 8px 0;
        }
        .comment { color: #6a737d; }
        .section-title {
            font-size: 14px;
            color: #666;
            margin: 16px 0 8px 0;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
    </style>
</head>
<body>
    <h1 style="text-align: center; margin-bottom: 20px;">🔷 Ton.Place App Demo</h1>

    {{if .Error}}
    <div class="error">
        <strong>Error:</strong> {{.Error}}
    </div>
    {{end}}

    {{if .IsAuthorized}}
    <!-- ============================================================== -->
    <!-- USER INFO SECTION                                              -->
    <!-- Shows the data that Ton.Place passes to your app               -->
    <!-- ============================================================== -->
    <div class="card">
        <h2>👤 User Information</h2>
        <p class="section-title">Data received from Ton.Place:</p>
        <div class="info-row">
            <span class="label">User ID</span>
            <span class="value">{{.User.UserID}}</span>
        </div>
        <div class="info-row">
            <span class="label">First Name</span>
            <span class="value">{{.User.FirstName}}</span>
        </div>
        <div class="info-row">
            <span class="label">Last Name</span>
            <span class="value">{{.User.LastName}}</span>
        </div>
        <div class="info-row">
            <span class="label">App ID</span>
            <span class="value">{{.User.AppID}}</span>
        </div>
        <div class="info-row">
            <span class="label">Timestamp</span>
            <span class="value">{{.User.Timestamp}}</span>
        </div>
        <div class="info-row">
            <span class="label">Signature Valid</span>
            <span class="value" style="color: green;">✓ Verified</span>
        </div>
    </div>

    <!-- ============================================================== -->
    <!-- PAYMENT SECTION                                                -->
    <!-- Demonstrates how to create purchases and process payments      -->
    <!-- ============================================================== -->
    <div class="card">
        <h2>💳 Payment Demo</h2>

        <p class="section-title">How it works:</p>
        <div class="code-block">
            <span class="comment">// 1. Create purchase on your backend</span><br>
            fetch('/api/create-purchase', {<br>
            &nbsp;&nbsp;method: 'POST',<br>
            &nbsp;&nbsp;body: JSON.stringify({<br>
            &nbsp;&nbsp;&nbsp;&nbsp;user_id: {{.User.UserID}},<br>
            &nbsp;&nbsp;&nbsp;&nbsp;amount: 100, <span class="comment">// 1.00 EUR in cents</span><br>
            &nbsp;&nbsp;&nbsp;&nbsp;title: "Premium Feature"<br>
            &nbsp;&nbsp;})<br>
            });<br><br>
            <span class="comment">// 2. Open payment dialog with SDK</span><br>
            TonPlace.purchase(purchaseId, onSuccess);
        </div>

        <button class="btn" onclick="makePurchase()">
            💰 Pay 1.00 EUR (Demo)
        </button>

        <p style="font-size: 12px; color: #666; margin-top: 8px;">
            This will create a real purchase request. You'll see the payment dialog.
        </p>
    </div>

    <!-- ============================================================== -->
    <!-- SDK METHODS DEMO                                               -->
    <!-- Shows other available SDK methods                              -->
    <!-- ============================================================== -->
    <div class="card">
        <h2>🛠 SDK Methods Demo</h2>

        <p class="section-title">TonPlace.shareApp()</p>
        <div class="code-block">
            <span class="comment">// Opens share dialog for your app</span><br>
            TonPlace.shareApp();
        </div>
        <button class="btn btn-secondary" onclick="shareApp()">
            📤 Share This App
        </button>

        <p class="section-title" style="margin-top: 16px;">TonPlace.createPost()</p>
        <div class="code-block">
            <span class="comment">// Opens post creation with pre-filled text</span><br>
            TonPlace.createPost('Check out this app!');
        </div>
        <button class="btn btn-secondary" onclick="createPost()">
            ✏️ Create Post About App
        </button>
    </div>

    <!-- ============================================================== -->
    <!-- TRANSACTIONS SECTION                                           -->
    <!-- Shows user's purchase history                                  -->
    <!-- ============================================================== -->
    <div class="card">
        <h2>📜 Transaction History</h2>
        <p class="section-title">Your purchases in this app:</p>

        <div id="transactions-list">
        {{if .Transactions}}
            {{range .Transactions}}
            <div class="transaction">
                <div class="transaction-header">
                    <span class="transaction-title">{{.Title}}</span>
                    <span class="transaction-amount">{{formatAmount .Amount .Currency}}</span>
                </div>
                <div class="transaction-meta">
                    ID: {{.ID}} |
                    <span class="status {{if eq .Status "paid"}}status-paid{{else}}status-pending{{end}}">
                        {{.Status}}
                    </span> |
                    {{formatTime .CreatedAt}}
                </div>
            </div>
            {{end}}
        {{else}}
            <p style="color: #666; text-align: center; padding: 20px;">
                No transactions yet. Try making a payment above!
            </p>
        {{end}}
        </div>

        <button class="btn btn-secondary" onclick="refreshTransactions()" style="margin-top: 12px;">
            🔄 Refresh Transactions
        </button>
    </div>

    <!-- ============================================================== -->
    <!-- API REFERENCE SECTION                                          -->
    <!-- Quick reference for developers                                 -->
    <!-- ============================================================== -->
    <div class="card">
        <h2>📚 API Quick Reference</h2>

        <p class="section-title">Authentication Headers (for backend API calls):</p>
        <div class="code-block">
            App-Id: YOUR_APP_ID<br>
            Secret: YOUR_APP_SECRET
        </div>

        <p class="section-title">GET /apps/purchases - List Transactions</p>
        <div class="code-block">
            <span class="comment">// Query parameters (all optional):</span><br>
            count=20      <span class="comment">// max 100</span><br>
            last_id=0     <span class="comment">// for pagination</span><br>
            status=paid   <span class="comment">// "pending" or "paid"</span><br>
            userId=123    <span class="comment">// filter by user</span>
        </div>

        <p class="section-title">POST /apps/purchase/create - Create Purchase</p>
        <div class="code-block">
            {<br>
            &nbsp;&nbsp;"amount": 100,    <span class="comment">// required, in cents</span><br>
            &nbsp;&nbsp;"currency": "eur", <span class="comment">// required</span><br>
            &nbsp;&nbsp;"title": "...",    <span class="comment">// required, max 150 chars</span><br>
            &nbsp;&nbsp;"user_id": 123     <span class="comment">// required</span><br>
            }
        </div>

        <p class="section-title">SDK Methods:</p>
        <div class="code-block">
            TonPlace.purchase(purchaseId, onSuccess)<br>
            TonPlace.shareApp()<br>
            TonPlace.createPost(text)
        </div>
    </div>

    {{else}}
    <!-- ============================================================== -->
    <!-- NOT AUTHORIZED STATE                                           -->
    <!-- Shown when app is opened directly without Ton.Place params     -->
    <!-- ============================================================== -->
    <div class="card">
        <h2>ℹ️ How to Use This Demo</h2>
        <p style="margin-bottom: 16px;">
            This app must be opened from <strong>Ton.Place</strong> to work properly.
        </p>
        <p style="margin-bottom: 16px;">
            When opened from Ton.Place, the following parameters are passed to your app URL:
        </p>
        <div class="code-block">
            ?app_id=123<br>
            &user_id=456<br>
            &ts=1707981234<br>
            &first_name=John<br>
            &last_name=Doe<br>
            &hash=abc123...
        </div>
        <p style="margin-top: 16px;">
            The <code>hash</code> parameter is an HMAC-SHA256 signature that you must verify
            on your backend to ensure the request is authentic.
        </p>
    </div>
    {{end}}

    <!-- ============================================================== -->
    <!-- JAVASCRIPT                                                     -->
    <!-- Client-side logic for interacting with SDK and backend         -->
    <!-- ============================================================== -->
    <script>
        // Store user ID for API calls (convert to number, template returns string)
        var userId = parseInt('{{.User.UserID}}', 10) || 0;

        /**
         * Creates a purchase and opens payment dialog
         *
         * Flow:
         * 1. Call our backend to create a purchase (returns purchase_id)
         * 2. Call TonPlace.purchase(purchase_id) to open payment dialog
         * 3. Wait for success/error callback
         * 4. Refresh transactions to see the result
         */
        function makePurchase() {
            // Step 1: Create purchase on backend
            fetch('/api/create-purchase', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    user_id: userId,
                    amount: 100,  // 1.00 EUR in cents
                    title: 'Demo Purchase'
                })
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.error) {
                    alert('Error: ' + data.error);
                    return;
                }

                // Step 2: Open payment dialog with SDK
                // TonPlace.purchase(purchaseId, onSuccess)
                TonPlace.purchase(
                    data.purchase_id,
                    function(result) {
                        // Payment successful!
                        alert('Payment successful!');
                        refreshTransactions();
                    }
                );
            })
            .catch(function(error) {
                alert('Network error: ' + error);
            });
        }

        /**
         * Opens share dialog for the app
         * Users can share your app with friends
         */
        function shareApp() {
            TonPlace.shareApp();
        }

        /**
         * Opens post creation dialog with pre-filled text
         * Great for viral marketing
         */
        function createPost() {
            TonPlace.createPost('I just tried this awesome app on Ton.Place!');
        }

        /**
         * Refreshes the transaction list
         * Use this for polling after payment
         */
        function refreshTransactions() {
            fetch('/api/transactions?user_id=' + userId)
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.error) {
                    console.error('Error:', data.error);
                    return;
                }

                // Update the transactions list
                var container = document.getElementById('transactions-list');
                if (!data.transactions || data.transactions.length === 0) {
                    container.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">No transactions yet.</p>';
                    return;
                }

                var html = '';
                data.transactions.forEach(function(tx) {
                    var amount = tx.currency === 'ton'
                        ? (tx.amount / 1000000000).toFixed(2) + ' TON'
                        : (tx.amount / 100).toFixed(2) + ' EUR';
                    var statusClass = tx.status === 'paid' ? 'status-paid' : 'status-pending';
                    var date = new Date(tx.created_at * 1000).toLocaleString();

                    html += '<div class="transaction">' +
                        '<div class="transaction-header">' +
                            '<span class="transaction-title">' + (tx.title || 'Purchase') + '</span>' +
                            '<span class="transaction-amount">' + amount + '</span>' +
                        '</div>' +
                        '<div class="transaction-meta">' +
                            'ID: ' + tx.id + ' | ' +
                            '<span class="status ' + statusClass + '">' + tx.status + '</span> | ' +
                            date +
                        '</div>' +
                    '</div>';
                });
                container.innerHTML = html;
            })
            .catch(function(error) {
                console.error('Fetch error:', error);
            });
        }

        // Optional: Auto-refresh transactions every 10 seconds
        // Uncomment this if you want automatic polling
        // setInterval(refreshTransactions, 10000);
    </script>
</body>
</html>`

// ====================================================================================
// MAIN
// ====================================================================================

func main() {
	// Log startup
	log.Printf("Starting Ton.Place Demo App on port %s", SERVER_PORT)
	log.Printf("App ID: %s", APP_ID)

	// Check configuration
	if APP_ID == "YOUR_APP_ID" || APP_SECRET == "YOUR_APP_SECRET" {
		log.Println("⚠️  WARNING: Please set your APP_ID and APP_SECRET before running in production!")
	}

	// Register HTTP handlers
	http.HandleFunc("/", handleIndex)                             // Main page with auth
	http.HandleFunc("/api/create-purchase", handleCreatePurchase) // Create purchase endpoint
	http.HandleFunc("/api/transactions", handleGetTransactions)   // Get transactions for polling

	// Start server
	log.Printf("Server running at http://localhost%s", SERVER_PORT)
	log.Fatal(http.ListenAndServe(SERVER_PORT, nil))
}

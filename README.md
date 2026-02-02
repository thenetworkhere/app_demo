# Ton.Place Mini App Demo

Demo application showing how to integrate with Ton.Place platform. This code serves as documentation for developers who want to build their own Ton.Place mini apps.

## Features

- User authorization via HMAC-SHA256 signature verification
- Creating purchases (payment requests)
- Processing payments via TonPlace SDK
- Fetching transaction history via Public API
- Social features: sharing app, creating posts

## Quick Start

### 1. Get Your App Credentials

1. Go to [ton.place/apps/manage](https://ton.place/apps)
2. Create a new app
3. Copy your `App ID` and `Secret`

### 2. Configure the Demo

Edit `main.go` and replace the placeholder values:

```go
const (
    APP_ID     = "YOUR_APP_ID"      // Your numeric app ID
    APP_SECRET = "YOUR_APP_SECRET"  // Your 32-character secret key
)
```

### 3. Run the Server

```bash
go run main.go
```

Server starts at `http://localhost:8080`

### 4. Test in Ton.Place

Your app URL in Ton.Place settings should point to your server. When users open your app from Ton.Place, they will be redirected with authorization parameters.

---

## Authorization

When a user opens your app from Ton.Place, the platform appends authorization parameters to your URL:

```
https://yourapp.com/?app_id=1&user_id=123&ts=1707981234&first_name=John&last_name=Doe&hash=abc123...
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `app_id` | string | Your application ID |
| `user_id` | string | User's unique ID on Ton.Place |
| `ts` | string | Unix timestamp when signature was created |
| `first_name` | string | User's first name (may be empty) |
| `last_name` | string | User's last name (may be empty) |
| `hash` | string | HMAC-SHA256 signature |

### Signature Verification Algorithm

**IMPORTANT:** Always verify the signature on your backend to ensure the request is authentic.

```go
func VerifySignature(queryParams map[string][]string, secret string) bool {
    // 1. Collect ALL query parameters except "hash"
    paramsMap := make(map[string]string)
    for key, values := range queryParams {
        if key == "hash" {
            continue
        }
        if len(values) > 0 {
            paramsMap[key] = values[0]
        }
    }

    // 2. Sort keys alphabetically
    keys := make([]string, 0, len(paramsMap))
    for key := range paramsMap {
        keys = append(keys, key)
    }
    sort.Strings(keys)

    // 3. Build check string: "key1=value1\nkey2=value2\n..."
    var checkStr string
    for i, key := range keys {
        if i > 0 {
            checkStr += "\n"
        }
        checkStr += key + "=" + paramsMap[key]
    }

    // 4. Hash the secret with SHA256
    secretHasher := sha256.New()
    secretHasher.Write([]byte(secret))
    secretKey := secretHasher.Sum(nil)

    // 5. Create HMAC-SHA256 signature
    h := hmac.New(sha256.New, secretKey)
    h.Write([]byte(checkStr))
    expectedHash := hex.EncodeToString(h.Sum(nil))

    // 6. Compare with provided hash
    return hmac.Equal([]byte(expectedHash), []byte(providedHash))
}
```

**Key points:**
- Use ALL parameters from the request, not a hardcoded list
- Sort parameters alphabetically
- Join with newlines (`\n`), format: `key=value`
- SHA256 hash the secret first, then use it as HMAC key
- Always validate timestamp to prevent replay attacks (recommended: 5 minutes max age)

---

## Public API

Base URL: `https://api.tonplace.net`

### Authentication

All API requests require these headers:

```
App-Id: YOUR_APP_ID
Secret: YOUR_APP_SECRET
```

### GET /apps/purchases

Fetch transaction history for your app.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `count` | int | No | Number of transactions (default: 20, max: 100) |
| `last_id` | int | No | Last transaction ID for pagination |
| `status` | string | No | Filter by status: `pending` or `paid` |
| `userId` | int | No | Filter by user ID |

**Response:**

```json
{
  "transactions": [
    {
      "id": 123,
      "amount": 100,
      "currency": "eur",
      "user_id": 456,
      "created_at": 1707981234,
      "status": "paid"
    }
  ]
}
```

### POST /apps/purchase/create

Create a new purchase request.

**Request Body:**

```json
{
  "amount": 100,
  "currency": "eur",
  "title": "Premium Feature",
  "user_id": 456
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `amount` | int64 | Yes | Amount in smallest unit (cents for EUR) |
| `currency` | string | Yes | Must be `eur` |
| `title` | string | Yes | Purchase description (max 150 chars) |
| `user_id` | int | Yes | User ID who will pay |

**Response:**

```json
{
  "purchase_id": 789
}
```

---

## JavaScript SDK

Include the SDK in your HTML:

```html
<script src="https://ton.place/app_sdk.js"></script>
```

### TonPlace.purchase(purchaseId, onSuccess)

Opens the payment dialog for a purchase.

```javascript
// 1. Create purchase on your backend
fetch('/api/create-purchase', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        user_id: 123,
        amount: 100,  // 1.00 EUR
        title: 'Premium Feature'
    })
})
.then(response => response.json())
.then(data => {
    // 2. Open payment dialog
    TonPlace.purchase(data.purchase_id, function(result) {
        console.log('Payment successful!');
    });
});
```

### TonPlace.shareApp()

Opens the share dialog for your app.

```javascript
TonPlace.shareApp();
```

### TonPlace.createPost(text)

Opens post creation dialog with pre-filled text.

```javascript
TonPlace.createPost('Check out this awesome app!');
```

---

## Currency Units

All amounts in the API are in **smallest currency units**:

| Currency | Smallest Unit | Example |
|----------|---------------|---------|
| EUR | cents | 100 = 1.00 EUR |
| TON | nanotons | 1000000000 = 1.00 TON |

**Conversion functions:**

```go
// EUR: 1 EUR = 100 cents
amountInCents := int64(euros * 100)
euros := float64(amountInCents) / 100

// TON: 1 TON = 1,000,000,000 nanotons
amountInNano := int64(ton * 1000000000)
ton := float64(amountInNano) / 1000000000
```

---

## Payment Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │     │ Your Server │     │  Ton.Place  │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │ 1. Click "Pay"    │                   │
       │──────────────────>│                   │
       │                   │                   │
       │                   │ 2. POST /apps/purchase/create
       │                   │──────────────────>│
       │                   │                   │
       │                   │ 3. { purchase_id } │
       │                   │<──────────────────│
       │                   │                   │
       │ 4. purchase_id    │                   │
       │<──────────────────│                   │
       │                   │                   │
       │ 5. TonPlace.purchase(id, callback)    │
       │──────────────────────────────────────>│
       │                   │                   │
       │                   │    6. Payment UI  │
       │                   │                   │
       │ 7. onSuccess callback                 │
       │<──────────────────────────────────────│
       │                   │                   │
       │ 8. Refresh transactions               │
       │──────────────────>│                   │
       │                   │ 9. GET /apps/purchases
       │                   │──────────────────>│
       │                   │                   │
```

---

## Security Best Practices

1. **Never expose your secret** on the client side or in public repositories
2. **Always verify signatures** on the backend before trusting user data
3. **Validate timestamps** to prevent replay attacks (5 min max age recommended)
4. **Use HTTPS** in production
5. **Validate all input** on your backend before creating purchases

---

## Project Structure

```
tonplace_app_demo/
├── main.go      # Complete demo application
├── README.md    # This documentation
└── go.mod       # Go module file
```

The entire demo is contained in a single `main.go` file for simplicity. In production, you would typically split this into multiple files/packages.

---

## License

MIT

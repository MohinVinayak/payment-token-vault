# Payment Token Vault

A lightweight, high-performance API service built to securely tokenize and detokenize sensitive credit card data (PANs). 

Instead of storing raw credit card numbers in a primary database, applications can send the data to this vault. The vault encrypts the original data, stores it securely, and returns a safe, non-sensitive "token" (along with a masked version of the card) that can be used for standard database operations.

## How It Works

* **Tokenization:** Validates the PAN using the Luhn algorithm, generates a deterministic hash (to prevent duplicate entries), encrypts the raw PAN using Fernet symmetric encryption, and returns a unique token.
* **Detokenization:** Requires elevated privileges (`admin` role). Takes a token, decrypts the underlying PAN, and logs the access reason.
* **Role-Based Access:** Enforces strict role checks. Standard services can tokenize data, but only admins can detokenize it.
* **Audit Logging:** Every tokenization and detokenization attempt (successful or denied) is logged in the database for security auditing.

## Tech Stack

* **Framework:** FastAPI (Asynchronous, high-performance ASGI)
* **Encryption:** `cryptography` (Fernet symmetric encryption, HMAC-SHA256)
* **Database:** SQLite (Lightweight, local repository)
* **Testing:** Pytest & FastAPI TestClient

## Local Setup

1. **Clone and enter the directory:**
   ```powershell
   git clone <your-repo-url>
   cd payment-token-vault
   ```

2. **Set up the virtual environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```powershell
   pip install fastapi[standard] cryptography python-dotenv pytest
   ```

4. **Environment Variables:**
   Create a `.env` file in the root directory and add your secret keys:
   ```env
   FERNET_KEY=your_url_safe_base64_encoded_32_byte_key
   HMAC_SECRET=your_secure_random_secret_string
   ```

5. **Run the Server:**
   ```powershell
   uvicorn app.main:app --reload
   ```

6. **View the Docs:**
   Open a browser and navigate to `http://127.0.0.1:8000/docs` to test the API directly through the Swagger UI.
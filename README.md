# FastAPI Starter

Deploy your [FastAPI](https://fastapi.tiangolo.com/) project to Vercel with zero configuration.

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/vercel/vercel/tree/main/examples/fastapi&template=fastapi)

_Live Example: https://vercel-plus-fastapi.vercel.app/_

Visit the [FastAPI documentation](https://fastapi.tiangolo.com/) to learn more.

## Getting Started

Install the required dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install .
```

Or, if using [uv](https://docs.astral.sh/uv/):

```bash
uv sync
```


## Running Locally

Start the development server on http://0.0.0.0:5001

```bash
python main.py
# using uv:
uv run main.py
```

When you make changes to your project, the server will automatically reload.

## Deploying to Vercel

Deploy your project to Vercel with the following command:

```bash
npm install -g vercel
vercel --prod
```

Or `git push` to your repository with our [git integration](https://vercel.com/docs/deployments/git).

To view the source code for this template, [visit the example repository](https://github.com/vercel/vercel/tree/main/examples/fastapi).

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

## Supabase Authentication Setup

This project includes Supabase authentication for user registration and login.

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Supabase

1. Create a project at [Supabase](https://app.supabase.com/)
2. Get your project URL and API keys from Settings > API
3. Create a `.env` file in the root directory:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key-here
SUPABASE_SERVICE_KEY=your-service-role-key-here
SECRET_KEY=your-secret-key-change-in-production
```

### 3. Authentication Endpoints

All authentication endpoints are available under `/api/v1/auth`:

- **POST `/api/v1/auth/register`** - Register a new user
  ```json
  {
    "email": "user@example.com",
    "password": "securepassword",
    "full_name": "John Doe"  // optional
  }
  ```

- **POST `/api/v1/auth/login`** - Login user
  ```json
  {
    "email": "user@example.com",
    "password": "securepassword"
  }
  ```

- **GET `/api/v1/auth/me`** - Get current user (requires Bearer token)
  ```
  Authorization: Bearer <access_token>
  ```

- **POST `/api/v1/auth/logout`** - Logout user

### 4. Using Protected Endpoints

To protect your endpoints, use the `get_current_user` dependency:

```python
from app.dependencies import get_current_user

@router.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": f"Hello {current_user['email']}"}
```

### 5. Testing Authentication

You can test the authentication endpoints using:
- The interactive API docs at `/docs`
- curl or any HTTP client
- Postman or similar tools

Example with curl:
```bash
# Register
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Login
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Get current user (use token from login response)
curl -X GET "http://localhost:8000/api/v1/auth/me" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Shopify Webhook Integration

The API includes webhook endpoints to automatically register Shopify customers in Supabase.

### 1. Configure Shopify Webhook Secret

Add to your `.env` file:

```env
SHOPIFY_WEBHOOK_SECRET=your-shopify-webhook-secret
```

### 2. Set Up Webhook in Shopify

1. Go to your Shopify Admin → Settings → Notifications
2. Scroll down to "Webhooks"
3. Create a new webhook:
   - **Event**: Customer creation
   - **Format**: JSON
   - **URL**: `https://your-domain.com/api/v1/webhooks/shopify/customers/create`
   - **API version**: Latest

### 3. Webhook Endpoints

- **POST `/api/v1/webhooks/shopify/customers/create`** - Automatically registers new Shopify customers in Supabase
  - Extracts customer email, name, phone from Shopify
  - Creates user in Supabase with temporary password
  - Stores Shopify customer ID in user metadata

- **POST `/api/v1/webhooks/shopify/customers/update`** - Handles customer updates from Shopify

### 4. Webhook Security

The webhook verifies the Shopify signature using `X-Shopify-Hmac-Sha256` header. Make sure to:
- Set `SHOPIFY_WEBHOOK_SECRET` in your `.env` file
- Use the same secret configured in your Shopify webhook settings

### 5. Testing Webhooks

You can test webhooks using Shopify's webhook testing or by sending a POST request:

```bash
curl -X POST "http://localhost:8000/api/v1/webhooks/shopify/customers/create" \
  -H "Content-Type: application/json" \
  -H "X-Shopify-Shop-Domain: your-shop.myshopify.com" \
  -H "X-Shopify-Topic: customers/create" \
  -H "X-Shopify-Hmac-Sha256: YOUR_SIGNATURE" \
  -d '{
    "customer": {
      "id": 123456,
      "email": "customer@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "phone": "+1234567890"
    }
  }'
```

**Note**: When a customer is created via webhook, they receive a temporary password. Consider implementing a password reset flow for these users.

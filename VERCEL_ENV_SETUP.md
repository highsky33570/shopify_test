# Vercel Environment Variables Setup

## Why `.env` files don't work on Vercel

**Important**: `.env` files are for **local development only**. Vercel does NOT read `.env` files from your repository because:

1. **Security**: `.env` files contain secrets and should never be committed to git
2. **Platform-specific**: Vercel injects environment variables directly into your application's runtime
3. **Different environments**: You can set different values for Production, Preview, and Development

The `load_dotenv()` in your code works locally but does nothing on Vercel. On Vercel, environment variables are automatically available via `os.getenv()`.

---

To fix the "supabase_url is required" error, you need to set environment variables in Vercel.

## Required Environment Variables

### 1. Go to Vercel Dashboard
1. Navigate to your project on [Vercel Dashboard](https://vercel.com/dashboard)
2. Go to **Settings** → **Environment Variables**

### 2. Add the following environment variables:

#### Supabase Configuration (Required)
```
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key-here
SUPABASE_SERVICE_KEY=your-service-role-key-here (optional, for admin operations)
```

#### Shopify Webhook (Optional)
```
SHOPIFY_WEBHOOK_SECRET=your-shopify-webhook-secret
```

#### Other (Optional)
```
SECRET_KEY=your-secret-key-for-jwt
```

## How to Get Supabase Credentials

1. Go to [Supabase Dashboard](https://app.supabase.com/)
2. Select your project
3. Go to **Settings** → **API**
4. Copy:
   - **Project URL** → `SUPABASE_URL`
   - **anon public** key → `SUPABASE_KEY`
   - **service_role** key → `SUPABASE_SERVICE_KEY` (optional)

## After Adding Environment Variables

1. **Redeploy your application** in Vercel:
   - Go to **Deployments** tab
   - Click the three dots (⋯) on the latest deployment
   - Select **Redeploy**
   - Or push a new commit to trigger a new deployment

2. Environment variables are automatically available to your application

## Verify Environment Variables

You can verify your environment variables are set by:
- Checking the Vercel deployment logs
- Testing your API endpoints
- The error message will now be more descriptive if variables are missing

## Important Notes

- Environment variables are case-sensitive
- Make sure there are no extra spaces when copying values
- For production, make sure to set variables for the **Production** environment
- You can also set different values for **Preview** and **Development** environments

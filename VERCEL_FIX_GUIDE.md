# 🔧 FIX: "SUPABASE_URL environment variable is not set" Error

## Quick Fix Steps

### Step 1: Verify Environment Variables in Vercel

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Select your project
3. Go to **Settings** → **Environment Variables**
4. **VERIFY** these variables exist:
   - `SUPABASE_URL`
   - `SUPABASE_KEY`

### Step 2: Check Environment Scope

**CRITICAL**: Make sure variables are set for the correct environment:

- ✅ **Production** - For production deployments
- ✅ **Preview** - For preview deployments  
- ✅ **Development** - For local development

**If you only set them for "Development", they won't work in Production!**

### Step 3: Add Variables (if missing)

1. Click **Add New**
2. Add each variable:
   - **Key**: `SUPABASE_URL`
   - **Value**: `https://your-project.supabase.co`
   - **Environment**: Select **Production**, **Preview**, and **Development**
3. Repeat for `SUPABASE_KEY`

### Step 4: Redeploy

**IMPORTANT**: After adding/changing environment variables, you MUST redeploy:

1. Go to **Deployments** tab
2. Find your latest deployment
3. Click the **three dots (⋯)** menu
4. Click **Redeploy**
5. Wait for deployment to complete

### Step 5: Verify with Debug Endpoint

After redeploying, test the debug endpoint:

```
GET https://your-app.vercel.app/api/v1/debug/env-check
```

This will show you:
- If environment variables are set
- Their values (partially masked for security)
- Validation status

## Common Issues

### Issue 1: Variables set but still not working

**Solution**: 
- Make sure you selected **Production** environment when adding variables
- **Redeploy** after adding variables (they don't apply to existing deployments)

### Issue 2: Variables show in dashboard but not accessible

**Solution**:
- Check for typos: `SUPABASE_URL` not `SUPABASE-URL` or `supabase_url`
- Environment variables are case-sensitive
- Remove and re-add the variables
- Redeploy

### Issue 3: Works locally but not on Vercel

**Solution**:
- Local uses `.env` file
- Vercel uses dashboard environment variables
- They are separate - you need to set both

## Get Your Supabase Credentials

1. Go to [Supabase Dashboard](https://app.supabase.com/)
2. Select your project
3. Go to **Settings** → **API**
4. Copy:
   - **Project URL** → Use for `SUPABASE_URL`
   - **anon public** key → Use for `SUPABASE_KEY`

## Verification Checklist

- [ ] Variables added in Vercel Dashboard
- [ ] Variables set for **Production** environment
- [ ] No typos in variable names
- [ ] Values copied correctly (no extra spaces)
- [ ] Redeployed after adding variables
- [ ] Debug endpoint shows variables are set
- [ ] Test login endpoint again

## Still Not Working?

1. Check Vercel deployment logs for errors
2. Use the debug endpoint: `/api/v1/debug/env-check`
3. Verify variable names match exactly (case-sensitive)
4. Try removing and re-adding variables
5. Make sure you're testing the correct deployment (Production vs Preview)

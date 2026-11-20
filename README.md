Circle — Customer Management Dashboard

A full-stack web application where every user gets a private workspace to manage their own customers: add, view, edit, delete and search, with secure authentication, a personal profile page and profile photo upload.

Built with Node.js, Express, MongoDB and EJS.

Features:

Authentication & accounts

Sign up, sign in and sign out
Passwords hashed with bcrypt
Session-based login, with sessions stored in MongoDB so users stay signed in across server restarts
Every page is protected by an authentication middleware; only /signin, /signup and /demo are public

Customer management

Add, view, edit and delete customers
Search customers by first name (case-insensitive, special characters escaped)
Delete confirmation modal
Each customer belongs to one user, and every query is scoped to the logged-in account, so nobody can read or change another user's data

Profile

Personal profile page with stats (total customers, member since)
Edit name, phone and company
Profile photo upload (JPG, PNG or WEBP, up to 2 MB) with a camera button on the avatar; the photo is stored in MongoDB and shown in the sidebar on every page
Letter avatar fallback when no photo is set

Live demo account

One click creates a temporary account pre-filled with 8 sample customers
Demo accounts and their data are removed automatically after 24 hours using MongoDB TTL indexes

UI

Responsive layout built with Bootstrap 5
Collapsible sidebar
Light / dark / auto theme toggle
Custom-designed sign in, sign up and profile pages

Security:
Passwords are never stored in plain text (bcrypt, 10 salt rounds)
Generic login error ("Invalid email or password") so attackers can't tell which emails exist
Rate limiting on sign in, sign up and demo routes (20 requests per 15 minutes per IP)
Security headers via helmet
Session cookies are httpOnly, sameSite: lax, and secure in production
Updates accept only a whitelist of fields instead of the raw request body
User input is escaped in templates (EJS <%= %>) and in search regex
Uploads are limited by type and size
Secrets live in environment variables and are never committed

Live Demo: https://circle-ayaebaid.vercel.app/


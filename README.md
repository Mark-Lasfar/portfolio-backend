![Portfolio Backend Logo](https://raw.githubusercontent.com/Mark-Lasfar/portfolio-markk/3abf6a0ddd4c22814556390a9449452ef7ff7c91/frontend/public/assets/img/logo.svg)
# Portfolio Backend

This repository contains the backend for Ibrahim Al-Asfar's portfolio website, built with Express.js, MongoDB, and Cloudinary for file uploads. It supports authentication (JWT, Google, Facebook, GitHub), project management, skills, and an AI-powered chat system integrated with a FastAPI backend on Render.

## Features
- User authentication (email/password, Google, Facebook, GitHub OAuth)
- Project and skill management (CRUD operations)
- File uploads via Cloudinary
- AI-powered Q&A and conversation system
- Commenting system with admin replies
- Email notifications via Nodemailer

## Prerequisites
- Node.js (>= 14.x)
- MongoDB Atlas account
- Cloudinary account
- Google, Facebook, and GitHub OAuth credentials
- Gmail account for Nodemailer
- Hugging Face account for AI model access
- Render account for AI backend deployment

## Setup
 Clone the repository:
   ```bash
   git clone https://github.com/Mark-Lasfar/portfolio-backend.git
   cd portfolio-backend

```
## API Endpoints
- POST /api/login: Login with email and password
- POST /api/register: Register a new user
- GET /auth/google: Start Google OAuth flow
- GET /auth/facebook: Start Facebook OAuth flow
- GET /auth/github: Start GitHub OAuth flow
- POST /api/upload: Upload files to Cloudinary (requires authentication)
- POST /api/ask: Ask a question to the AI backend
- POST /api/converse: Continue a conversation with the AI
- GET /api/projects: Get all projects
- POST /api/projects: Create a new project (admin only)
- PUT /api/projects/:projectId: Update a project (admin only)
- DELETE /api/projects/:projectId: Delete a project (admin only)
- GET /api/comments/:projectId: Get comments for a project
- POST /api/comments: Add a comment (requires authentication)
- POST /api/comments/:commentId/reply: Reply to a comment (admin only)
- DELETE /api/comments/:commentId: Delete a comment (admin only)
- GET /api/skills: Get all skills
- POST /api/skills: Create a new skill (admin only)
- PUT /api/skills/:skillId: Update a skill (admin only)
- DELETE /api/skills/:skillId: Delete a skill (admin only)

## License

MIT License
## Contact

For issues or questions, contact Mark Al-Asfar.

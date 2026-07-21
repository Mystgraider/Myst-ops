# File: frontend/Dockerfile

# Stage 1: Build the React application
FROM node:18-alpine AS build

# Install build dependencies that may be needed for native modules
RUN apk add --no-cache python3 make g++

# Set the working directory
WORKDIR /app

# Copy package.json AND package-lock.json first
COPY package*.json ./

# Copy configuration files
COPY tailwind.config.js ./
COPY postcss.config.js ./

# Install dependencies using npm ci for reproducible builds
# Fall back to npm install if package-lock.json is missing
RUN if [ -f package-lock.json ]; then npm ci --prefer-offline --no-audit; else npm install --prefer-offline --no-audit; fi

# Copy the rest of the application code
COPY . .

# Build the application with production environment
RUN npm run build

# Stage 2: Serve the application with Nginx
FROM nginx:1.25-alpine

# Copy the build output from the build stage to Nginx's web server directory
COPY --from=build /app/build /usr/share/nginx/html

# Copy nginx configuration as a template - the official nginx image auto-runs
# envsubst on anything in /etc/nginx/templates/*.template at container start,
# substituting ${BACKEND_HOST} (and any other env var actually set) before
# writing the real config to /etc/nginx/conf.d/. No custom entrypoint needed.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

# Default for local docker-compose; override with -e BACKEND_HOST=host:port
# (or a platform's env var UI) when deploying the two services separately.
ENV BACKEND_HOST=backend:3001

# Expose port 80
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
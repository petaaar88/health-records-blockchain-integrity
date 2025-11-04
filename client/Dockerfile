# Use official Node.js image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy all project files
COPY . .

# Expose default Vite port
EXPOSE 5173

# Run Vite dev server (bind to 0.0.0.0 so it's accessible outside)
CMD ["npm", "run", "dev", "--", "--host"]

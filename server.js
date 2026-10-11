// server.js
// Starts the app: connects to MongoDB first, then listens for requests.

const app = require("./src/app");
const { env } = require("./src/config/env");
const { connectDB } = require("./src/config/db");

async function startServer() {
  try {
    await connectDB(env.MONGODB_URI);
    app.listen(env.PORT, () => {
      console.log(`Server running at http://localhost:${env.PORT}`);
    });
  } catch (error) {
    console.error("Failed to start the server:", error.message);
    process.exit(1);
  }
}

startServer();
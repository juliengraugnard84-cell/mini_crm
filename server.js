const express = require("express");
const { createServer } = require("http");

const app = express();
const httpServer = createServer(app);
let io = null;

try {
  const { Server } = require("socket.io");
  io = new Server(httpServer, {
    cors: {
      origin: "*",
    },
  });
} catch (error) {
  console.warn("socket.io absent: demarrage du serveur sans websocket.");
}

if (io) {
  io.on("connection", (socket) => {
    console.log("Client connecte:", socket.id);

    socket.on("message", (msg) => {
      io.emit("message", msg);
    });

    socket.on("disconnect", () => {
      console.log("Client deconnecte:", socket.id);
    });
  });
}

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    websocket: Boolean(io),
  });
});

const PORT = process.env.PORT || 3001;

httpServer.listen(PORT, () => {
  console.log("Chat server active on port", PORT);
});

module.exports = httpServer;
